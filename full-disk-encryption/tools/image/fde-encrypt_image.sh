#!/bin/bash

# Copyright (C) 2025 Intel Corporation
# SPDX-License-Identifier: BSD-3-Clause

# Summary of the Script
# This script is designed to handle full-disk encryption for a TDX guest image.
# Below is a summary of the script's functionality.

# It performs the following main tasks:
# - cleanup_get_quote: Cleans up any remnants from a previous run, including unmounting partitions, disconnecting devices, and removing temporary files.
# - create_image: Creates an empty image file of the calculated size based on the specified partition sizes.
# - create_partitions: Sets up the partition layout for BIOS, UEFI, boot, and root filesystem in the created image and maps it to a loop device.
# - create_luks_partition: Encrypts the root partition with LUKS using provided key and opens it to a virtual device.
# - format_partitions: Formats the EFI, boot, and decrypted root partitions.
# - fill_rootfs: Copies data from the base image to the root partition, mounts necessary partitions, and sets up the root filesystem.
# - close_partitions: Closes the virtual device providing decrypted access to the root partition and detaches the loop device.
# - modify_ovmf: Enrolls public key from key pair used for key retrieval, KBS url & KBS key path where key to be stored in KMS into the OVMF firmware.

MY_PATH="$(dirname "$(readlink -f "$0")")"
pushd "${MY_PATH}"

# Determine the username of the user who initiated the script, even if it is being run with elevated privileges.
if [[ -z "$SUDO_USER" ]]; then
    LOGIN_USER=$(whoami)
else
    LOGIN_USER=$SUDO_USER
fi

# Define temporary directories used for following steps
PATH_TMP_DIR="$MY_PATH/tmp_fde"
PATH_MNT_ROOTFS="${PATH_TMP_DIR}/mnt_root"
PATH_MNT_BOOT="${PATH_MNT_ROOTFS}/boot"
PATH_MNT_EFI="${PATH_MNT_BOOT}/efi"
PATH_MNT_NBT="${PATH_TMP_DIR}/mnt_nbd"

# Define labels for encrypted root partition and for virtual device providing decrypted access to this partition.
# Label uses a hash of the script directory to make it unique for the invocation of this script instance.
MY_PATH_HASH=$(echo -n "$MY_PATH" | md5sum | cut -c1-8)
LABEL_PART_ROOTFS_ENC="rootfs-enc_${MY_PATH_HASH}"
LABEL_DEV_ROOTFS_DEC="rootfs-enc-dev_${MY_PATH_HASH}"

# Size of key used to encrypt root filesystem.
EXPECTED_K_RFS_SIZE=256

# Function cleans after last GET_QUOTE run, which might have failed at any point.
function cleanup_get_quote() {
    local PATH_IMG_IN=$1

    # Unmount anything mounted to directory used to mount partition from base image.
    if mount | grep -q "$PATH_MNT_NBT"; then
        umount "$PATH_MNT_NBT"
    fi

    # If any nbd is connected to base image, disconnect it.
    local nbd_line=$(ps m -C qemu-nbd --no-headers | grep "$PATH_IMG_IN")
    if [ -n "$nbd_line" ]; then
        # Extract the nbd device (e.g., /dev/nbd0)
        local nbd_device
        nbd_device=$(echo "$nbd_line" | grep -oE '\-\-connect=/dev/nbd[0-9]+' | cut -d= -f2)

        if [ -n "$nbd_device" ]; then
            echo "Found \"$PATH_IMG_IN\" connected to \"$nbd_device\". Disconnecting..."

            qemu-nbd --disconnect "$nbd_device"
        fi
    fi

    # Check if output image is associated with any loop device.
    # If it is, find corresponding loop device and unmount partitions individually.
    if losetup -a | grep -q "$PATH_IMG_OUT"; then
        # To not accidentally unmount system folders, make sure that PATH_MNT_ROOTFS is defined and set to a path inside the project directory.
        [ -n "$PATH_MNT_ROOTFS" ] && [[ "$PATH_MNT_ROOTFS" == "$MY_PATH"* ]] || exit 1

        if mount | grep -q "${PATH_MNT_ROOTFS}/dev/pts"; then
            umount "${PATH_MNT_ROOTFS}/dev/pts"
        fi
        if mount | grep -q "${PATH_MNT_ROOTFS}/dev"; then
            umount "${PATH_MNT_ROOTFS}/dev"
        fi
        if mount | grep -q "${PATH_MNT_ROOTFS}/run"; then
            umount -f "${PATH_MNT_ROOTFS}/run"
        fi
        if mount | grep -q "${PATH_MNT_ROOTFS}/tmp"; then
            umount "${PATH_MNT_ROOTFS}/tmp"
        fi
        if mount | grep -q "${PATH_MNT_ROOTFS}/sys"; then
            umount -l "${PATH_MNT_ROOTFS}/sys"
        fi
        if mount | grep -q "${PATH_MNT_ROOTFS}/proc"; then
            umount "${PATH_MNT_ROOTFS}/proc"
        fi

        if mount | grep "${PATH_MNT_ROOTFS}" | grep -q "${PATH_MNT_EFI}"; then
            umount "${PATH_MNT_EFI}"
        fi
        if mount | grep "${PATH_MNT_ROOTFS}" | grep -q "${PATH_MNT_BOOT}"; then
            umount "${PATH_MNT_BOOT}"
        fi
        if mount | grep -q "${PATH_MNT_ROOTFS}"; then
            umount "${PATH_MNT_ROOTFS}"
        fi

        # Close virtual device providing a decrypted view to encrypted root partition.
        if cryptsetup status "$LABEL_DEV_ROOTFS_DEC" 2>/dev/null | grep -q "is active"; then
            cryptsetup close "$LABEL_DEV_ROOTFS_DEC" || echo "Warn: failed to close mapper $LABEL_DEV_ROOTFS_DEC"
        fi

        # Find all loop devices attached to the encrypted image and detach them.
        losetup -a | grep -F -- "$PATH_IMG_OUT" | cut -d: -f1 | while read -r loop_dev; do
            losetup -d "$loop_dev" || echo "Warn: failed to detach $loop_dev"
        done
    fi

    # If present, remove old output image.
    rm -f "$PATH_IMG_OUT"

    # If present, remove temporary folder is to prepare output image in last run
    rm -rf "$PATH_TMP_DIR"
}

function usage() {
    cat <<EOF
Usage: $(basename "$0") [OPTION]...

Options:
    -c <KBS_CERT_PATH>      Path to TLS certificate of Trustee KBS; mandatory argument.
    -p <PATH_IMG_IN>        Path to the input image; mandatory argument.
    -e <PATH_IMG_OUT>       Path to the output image; optional argument.
    -f <PK_KR_PATH>         Path to the public key from key pair used for key retrieval; mandatory argument.
    -u <KBS_URL>            URL of Trustee KBS; mandatory argument.
    -k <K_RFS_HEX>          Key for encryption of root filesystem in hex encoding; mandatory argument.
    -i <K_PATH>             Path used by Trustee KBS for root filesystem encryption key; mandatory argument.

    -r <SIZE_PART_ROOTFS>   Size of root filesystem partition; optional argument; default is 10GB
    -b <SIZE_PART_BOOT>     Size of boot partition; optional argument; default is 2GB

    -h                      Show this help
EOF
}

function process_args() {
    # Check if no arguments were provided
    if [[ $# -eq 0 ]]; then
        echo "No argument was provided"
        usage
        exit 1
    fi

    # Check if help option is provided anywhere in arguments
    for arg in "$@"; do
        if [[ "$arg" == "-h" ]]; then
            usage
            exit 0
        fi
    done

    while getopts "h:r:b:p:k:i:u:c:e:f:" option; do
        case "$option" in
        r) SIZE_PART_ROOTFS=$OPTARG ;;
        b) SIZE_PART_BOOT=$OPTARG ;;
        p) PATH_IMG_IN=$OPTARG ;;
        k) K_RFS_HEX=$OPTARG ;;
        i) K_PATH=$OPTARG ;;
        u) KBS_URL=$OPTARG ;;
        c) KBS_CERT_PATH=$OPTARG ;;
        e) PATH_IMG_OUT=$OPTARG ;;
        f) PK_KR_PATH=$OPTARG ;;
        h)
            usage
            exit 0
            ;;
        *)
            echo "Invalid option '-$OPTARG'"
            usage
            exit 1
            ;;
        esac
    done
}

check_params_filled() {
    local empty_vars=()

    # Loop through all arguments passed to the function.
    for var_name in "$@"; do
         # Indirect expansion to get the value of the variable
        local value="${!var_name}"
        if [ -z "$value" ]; then
            empty_vars+=("$var_name")
        fi
    done

    # Check if any variables are empty
    if [ ${#empty_vars[@]} -ne 0 ]; then
        echo "Error: The following mandatory parameters were not provided: ${empty_vars[*]}"
        usage
        exit 1
    fi

    return 0
}

# Function to check if specified parameters are empty and return an error if this is not the case.
check_params_empty() {
    local non_empty_vars=()

    # Loop through all arguments passed to the function.
    for var_name in "$@"; do
         # Indirect expansion to get the value of the variable
        local value="${!var_name}"
        if [ -n "$value" ]; then
            non_empty_vars+=("$var_name")
        fi
    done

    # Check if any variables are not empty
    if [ ${#non_empty_vars[@]} -ne 0 ]; then
        echo "Error: The following parameters should not be provided: ${non_empty_vars[*]}"
        usage
        exit 1
    fi

    return 0
}

# Check validity of provided arguments
function check_args_env() {
    check_params_filled PATH_IMG_IN KBS_CERT_PATH PK_KR_PATH KBS_URL K_PATH K_RFS_HEX

    if [ ! -f "$PATH_IMG_IN" ]; then
        echo "Input image not present at \"$PATH_IMG_IN\"."
        exit 1
    fi

    if [ ! -f "$PK_KR_PATH" ]; then
        echo "Public key from key pair used for key retrieval is not found at provided path \"$PK_KR_PATH\"."
        usage
        exit 1
    fi

    if [ ! -f "$KBS_CERT_PATH" ]; then
        echo "TLS certificate of Trustee KBS not found at provided path \"$KBS_CERT_PATH\"."
        usage
        exit 1
    fi

    if [[ ${#K_RFS_HEX} -ne $((EXPECTED_K_RFS_SIZE / 4)) ]]; then
        echo "Key for encryption of root filesystem must be ${EXPECTED_K_RFS_SIZE} bits long."
        usage
        exit 1
    fi

    # Input image must be an qcow2 image.
    if [[ "$PATH_IMG_IN" != *".qcow2" ]]; then
        echo "Error: The input file must have .qcow2 extension."
        exit 1
    fi

    if [ -z "$PATH_IMG_OUT" ]; then
        PATH_IMG_OUT="${PATH_IMG_IN%.*}_GET_QUOTE.img"
    else
        if [[ "$PATH_IMG_OUT" != *".img" ]]; then
            echo "Error: The output file must have .img extension."
            exit 1
        fi

        if [[ "$(realpath "$PATH_IMG_IN")" == "$(realpath "$PATH_IMG_OUT")" ]]; then
            echo "Error: The output image path cannot be the same as the input image path."
            exit 1
        fi
    fi
}

function modify_ovmf() {
    # Create virtual environment for Python if it does not already exist
    if [ -e my_venv/bin/activate ]; then
        echo "Found python virtual environment folder; using it"
        source my_venv/bin/activate
        if [[ -z "$(command -v ovmfkeyenroll)" ]]; then
            python3 -m pip install ovmfkeyenroll
        fi
    else
        python3 -m venv my_venv
        source my_venv/bin/activate
        python3 -m pip install ovmfkeyenroll
    fi

    rm -rf "${OVMF_OUTPUT}"

    # Enroll public key for key enrollment (PK_KR) to OVMF.
    VARIABLE_NAME="PK_KR"
    VARIABLE_GUID="4517e507-9b4b-479d-b422-2562900361e3"
    VARIABLE_VALUE_FILE_PATH="$PK_KR_PATH"
    python3 enroll_vars.py -i "${OVMF_INPUT}" -o "${OVMF_OUTPUT}" -n "$VARIABLE_NAME" -g "$VARIABLE_GUID" -d "$VARIABLE_VALUE_FILE_PATH"

    # Enroll URL of KBS to OVMF.
    printf "$KBS_URL" > kbs_url
    VARIABLE_NAME="KBSURL"
    VARIABLE_GUID="0d9b4a60-e0bf-4a66-b9b1-db1b98f87770"
    VARIABLE_VALUE_FILE_PATH="kbs_url"
    python3 enroll_vars.py -i "${OVMF_OUTPUT}" -o "${OVMF_OUTPUT}" -n "$VARIABLE_NAME" -g "$VARIABLE_GUID" -d "$VARIABLE_VALUE_FILE_PATH"

    # Enroll path to be used by Trustee KBS for root filesystem encryption key, to OVMF.
    printf "$K_PATH" > kbs_k_path
    VARIABLE_NAME="KBSKPATH"
    VARIABLE_GUID="dc001d1f-60a1-4e1e-853e-42e9ab0e8b88"
    VARIABLE_VALUE_FILE_PATH="kbs_k_path"
    python3 enroll_vars.py -i "${OVMF_OUTPUT}" -o "${OVMF_OUTPUT}" -n "$VARIABLE_NAME" -g "$VARIABLE_GUID" -d "$VARIABLE_VALUE_FILE_PATH"

    rm -rf kbs_url kbs_k_path

    deactivate
}

# Function sets partition layout for BIOS, UEFI, boot, and root filesystem in the passed image.
# It then maps the passed image to a loop device.
# Parameters:
#   - SIZE_PART_BOOT: The size of the boot partition.
#   - PATH_IMAGE: The path to the image file for which the partitions are set.
function create_partitions() {
    local SIZE_PART_BOOT=$1
    local PATH_IMAGE=$2

    local NUM_ROOTFS_PART=1
    local NUM_BIOS_PART=14
    local NUM_UEFI_PART=15
    local NUM_BOOT_PART=16

    # Set partition layout for BIOS, UEFI, boot, and root filesystem in the passed image.
    # Note that Root FS has to be defined last, because it used the remaining size.
    # Note that the install script later installs GRUB in the BIOS partition
    sgdisk --clear \
        --new "${NUM_BIOS_PART}::+1M" --typecode="${NUM_BIOS_PART}:ef02" --change-name="${NUM_BIOS_PART}:'bios'" \
        --new "${NUM_UEFI_PART}::+100M" --typecode="${NUM_UEFI_PART}:ef00" --change-name="${NUM_UEFI_PART}:'uefi'" \
        --new "${NUM_BOOT_PART}::+$SIZE_PART_BOOT" --typecode="${NUM_BOOT_PART}:8300" --change-name="${NUM_BOOT_PART}:'boot'" \
        --new "${NUM_ROOTFS_PART}::-0" --typecode="${NUM_ROOTFS_PART}:8300" --change-name="${NUM_ROOTFS_PART}:'rootfs'" \
        "$PATH_IMAGE"

    # Find an unused loop device and attach the image to it.
    local LOOPDEV
    LOOPDEV=$(losetup --find --show "$PATH_IMAGE")

    # Inform the operating system kernel of partition table changes of the image file.
    partprobe "${LOOPDEV}"

    # Return info about used loop device and name of created partitions.
    echo "${LOOPDEV}|${LOOPDEV}p${NUM_UEFI_PART}|${LOOPDEV}p${NUM_BOOT_PART}|${LOOPDEV}p${NUM_ROOTFS_PART}"
}

# Create a LUKS (Linux Unified Key Setup) encrypted partition.
# Parameters:
#   - PART: Partition to encrypt.
#   - LABEL_PART_ENC: Label of the encrypted partition.
#   - LABEL_DEV_DEC: Label of virtual device that provides a decrypted view of the data in the encrypted partition.
#   - KEY_HEX: Hex-encoded encryption key (256-bit for AES-256).
function create_luks_partition() {
    local PART=$1
    local LABEL_PART_ENC=$2
    local LABEL_DEV_DEC=$3
    local KEY_HEX=$4

    # Decode hex-encoded key, and set up an encrypted partition using LUKS2 with AES-GCM encryption using a 256bit key and AEAD for integrity protection.
    echo -n "$KEY_HEX" | xxd -r -p |
        cryptsetup -v -q luksFormat --encrypt --type luks2 \
            --cipher aes-gcm-random --integrity aead --key-size 256 "$PART"

    # Set a label for the encrypted partition
    cryptsetup -v config --label "$LABEL_PART_ENC" "$PART"

    # Decode hex-encoded key, and open the encrypted partition creating a virtual device providing decrypted access to encrypted partition.
    echo -n "$KEY_HEX" | xxd -r -p |
        cryptsetup luksOpen --key-size 256 "$PART" "${LABEL_DEV_DEC}"

    # Print/return path of virtual device providing decrypted access to encrypted partition.
    echo "/dev/mapper/${LABEL_DEV_DEC}"
}

# Format EFI partition, boot partition, and device providing decrypted access to encrypted root partition.
# Parameters:
#   - PART_EFI: EFI partition that should be formatted.
#   - PART_BOOT: Boot partition that should be formatted.
#   - DEV_ROOTFS_DEC: Virtual device providing a decrypted view to encrypted root partition that should be formatted.
function format_partitions() {
    local PART_EFI=$1
    local PART_BOOT=$2
    local DEV_ROOTFS_DEC=$3

    # Create filesystems for EFI partition.
    mkfs.fat -F32 "$PART_EFI"

    # Relabel because fat formatting cleared ext label.
    fatlabel "$PART_EFI" uefi

    # Format boot partition and device with access to encrypted root partition.
    mkfs.ext4 -F -L "boot" "$PART_BOOT"
    mkfs.ext4 -F "$DEV_ROOTFS_DEC"
}

# This function creates the root filesystem in virtual device providing decrypted access to encrypted root partition.
# It
# - Copies data from the base image to the root partition.
# - Copies the FDE solution binaries and data into the root partition.
# - Formats and prepares the root partition.
# - Mounts the boot and efi partitions inside the root partition.
# - Provides the necessary system interfaces and directories within the chroot environment.
# - Copies the installation script into the root partition and executes it.
function fill_rootfs() {
    local PART_EFI=$1
    local PART_BOOT=$2
    local DEV_ROOTFS_DEC=$3
    local PART_ROOTFS=$4
    local PATH_IMG_IN=$5
    local KBS_CERT_PATH=$6
    local LABEL_PART_ROOTFS_ENC=$7
    local LABEL_DEV_ROOTFS_DEC=$8

    # Ensures that the nbd module is available
    if ! lsmod | grep -wq nbd; then
        modprobe nbd max_part=8
    fi

    # Create temporary directory and mount virtual device providing decrypted access to encrypted root partition to this directory.
    mkdir -p "${PATH_MNT_ROOTFS}"
    mount "$DEV_ROOTFS_DEC" "${PATH_MNT_ROOTFS}"

    # Mount the boot partition inside the "boot" folder of the root partition.
    mkdir -p "${PATH_MNT_BOOT}"
    mount "$PART_BOOT" "${PATH_MNT_BOOT}/"

    # Mount the efi partition inside the "boot/efi" folder of the root partition.
    mkdir -p "${PATH_MNT_EFI}"
    mount "$PART_EFI" "${PATH_MNT_EFI}"

    # Cleanup files that are not needed
    rm -rf "${PATH_MNT_ROOTFS}/lost+found"
    rm -rf "${PATH_MNT_ROOTFS}/boot/lost+found"

    # Find the first unused network block device (nbd) and bind the base image to it.
    local UNUSED_DEV_NBD=""
    local TMP_DEV_NBD
    for TMP_DEV_NBD in /dev/nbd{0..15}; do
        # Check device is unused: not in /proc/mounts, no partition p1, and no partitions in lsblk
        if ! grep -q "$TMP_DEV_NBD" /proc/mounts \
            && [ ! -e "${TMP_DEV_NBD}p1" ] \
            && ! lsblk -n -o NAME "$TMP_DEV_NBD" 2>/dev/null | grep -q "${TMP_DEV_NBD##*/}p"; then
            UNUSED_DEV_NBD="$TMP_DEV_NBD"
            break
        fi
    done
    if [ -z "$UNUSED_DEV_NBD" ]; then
        echo "Error: No unused NBD device found."
        exit 1
    else
        echo "Using NBD device $UNUSED_DEV_NBD."
    fi
    qemu-nbd --connect="$UNUSED_DEV_NBD" "$PATH_IMG_IN"
    # Allow some time for the device to be ready
    sleep 3

    # Create a temporary directory that is used to mount partitions from the base image to.
    mkdir -p "${PATH_MNT_NBT}"

    mount "${UNUSED_DEV_NBD}p1" "${PATH_MNT_NBT}"
    # Detect Ubuntu version to use that to rename initrd and vmlinuz files later.
    local UBUNTU_VERSION
    UBUNTU_VERSION=$(grep DISTRIB_RELEASE "${PATH_MNT_NBT}/etc/lsb-release" | cut -d'=' -f2)
    # Copy the content of rootfs partition from base image to the rootfs partition.
    cp -rfp "${PATH_MNT_NBT}"/* "${PATH_MNT_ROOTFS}"
    umount "${PATH_MNT_NBT}"

    # Copy the content of the 16th partition of the base image to the boot directory in the root partition.
    mount "${UNUSED_DEV_NBD}p16" "${PATH_MNT_NBT}"
    cp -rf "${PATH_MNT_NBT}"/* "${PATH_MNT_BOOT}"
    umount "${PATH_MNT_NBT}"

    # Disconnect base image from nbd
    qemu-nbd --disconnect "${UNUSED_DEV_NBD}"

    # Copy FDE solution binaries into the root partition.
    pushd "${MY_PATH}/../../fde-binaries/"
    cp target/release/fde-decrypt-image "${PATH_MNT_ROOTFS}/sbin/"
    popd

    # Copy initramfs scripts, initramfs modules, and initramfs hooks into the root partition.
    pushd initramfs
    cp scripts/init-premount/fde-agent \
        "${PATH_MNT_ROOTFS}/usr/share/initramfs-tools/scripts/init-premount/"
    cp modules "${PATH_MNT_ROOTFS}/etc/initramfs-tools/"
    cp -r hooks/* "${PATH_MNT_ROOTFS}/usr/share/initramfs-tools/hooks/"
    popd

    # Copy a netplan into the root partition.
    cp netplan.yaml "${PATH_MNT_ROOTFS}/etc/netplan"

    # Copy KBS certificate into the root partition.
    cp "$KBS_CERT_PATH" "${PATH_MNT_ROOTFS}/etc/kbs.crt"

    # Provide the necessary system interfaces and directories within the chroot environment.
    mount -t proc none "${PATH_MNT_ROOTFS}/proc"
    mount -t sysfs none "${PATH_MNT_ROOTFS}/sys"
    mount -t tmpfs none "${PATH_MNT_ROOTFS}/tmp"
    mount --bind /run "${PATH_MNT_ROOTFS}/run"
    mount --bind /dev "${PATH_MNT_ROOTFS}/dev"
    mount --bind /dev/pts "${PATH_MNT_ROOTFS}/dev/pts"

    # Copy installation script into root partition, execute it, and remove it.
    cp scripts/install "${PATH_MNT_ROOTFS}/tmp/"
    chroot "${PATH_MNT_ROOTFS}/" /bin/bash tmp/install "$PART_ROOTFS" "$LABEL_PART_ROOTFS_ENC" "$LABEL_DEV_ROOTFS_DEC"
    rm "${PATH_MNT_ROOTFS}/tmp/install"

    echo "=============== Direct Boot LUKS Settings ============="
    local LUKS_UUID
    LUKS_UUID=$(cryptsetup luksUUID "$PART_ROOTFS")
    echo "export UUID=$LUKS_UUID"
    echo "export label=$LABEL_DEV_ROOTFS_DEC"

    # Extract initrd and vmlinuz.
    mkdir -p "${MY_PATH}"
    # Find the kernel version by looking for vmlinuz files in the boot directory and sorting them.
    local KERNEL_VERSION
    KERNEL_VERSION=$(find "${PATH_MNT_ROOTFS}/boot/" -name "vmlinuz-*-generic" 2>/dev/null \
        | "${PATH_MNT_ROOTFS}/usr/lib/grub/grub-sort-version" -r 2>/dev/null \
        | gawk 'match($0 , /^.*\/vmlinuz-(.*)/, a) {print a[1];exit}')
    
    local INITRD_PATH="${PATH_MNT_ROOTFS}/boot/initrd.img-${KERNEL_VERSION}"
    local VMLINUZ_PATH="${PATH_MNT_ROOTFS}/boot/vmlinuz-${KERNEL_VERSION}"

    if [[ -f "$INITRD_PATH" && -f "$VMLINUZ_PATH" ]]; then
        if [[ -z "$UBUNTU_VERSION" ]]; then
            UBUNTU_VERSION="24.04" # Default to 24.04 if not detected
        fi
        cp "$INITRD_PATH" "${MY_PATH}/initrd.img-${UBUNTU_VERSION}"
        cp "$VMLINUZ_PATH" "${MY_PATH}/vmlinuz-${UBUNTU_VERSION}"
        chmod +r "${MY_PATH}/vmlinuz-${UBUNTU_VERSION}"

        echo "initrd.img-${UBUNTU_VERSION} & vmlinuz-${UBUNTU_VERSION} copied and placed in ${MY_PATH}"
    else
        echo "Error: Kernel or initrd file not found for version ${KERNEL_VERSION}"
        ls "${PATH_MNT_ROOTFS}/boot/"

        umount "${PATH_MNT_ROOTFS}/dev/pts"
        umount "${PATH_MNT_ROOTFS}/dev"
        umount "${PATH_MNT_ROOTFS}/run"
        umount "${PATH_MNT_ROOTFS}/tmp"
        umount -l "${PATH_MNT_ROOTFS}/sys"
        umount "${PATH_MNT_ROOTFS}/proc"
        umount "${PATH_MNT_EFI}"
        umount "${PATH_MNT_BOOT}"
        umount -l "${PATH_MNT_ROOTFS}/"
        exit 1
    fi

    # Clean up mount points
    umount "${PATH_MNT_ROOTFS}/dev/pts"
    umount "${PATH_MNT_ROOTFS}/dev"
    umount "${PATH_MNT_ROOTFS}/run"
    umount "${PATH_MNT_ROOTFS}/tmp"
    umount -l "${PATH_MNT_ROOTFS}/sys"
    umount "${PATH_MNT_ROOTFS}/proc"
    umount "${PATH_MNT_EFI}"
    umount "${PATH_MNT_BOOT}"
    umount -l "${PATH_MNT_ROOTFS}/"
}

function close_partitions() {
    local DEV_ROOTFS_DEC=$1
    local LOOPDEV=$2

    # Close virtual device providing decrypted access to root partition.
    cryptsetup close "$DEV_ROOTFS_DEC"

    # Detach loop device .
    losetup -d "$LOOPDEV"
}

# Calculate the size of the output image based on specified partition size and create an empty image file of that size.
function create_image() {
    local SIZE_PART_ROOTFS=$1
    local SIZE_PART_BOOT=$2
    local PATH_IMG_OUT=$3

    # Calculate total image size in bytes based on defined size values.
    # Reserve 1MB for BIOS and 100MB for EFI.
    local SIZE_IMAGE
    SIZE_IMAGE=$(echo "($SIZE_PART_ROOTFS+$SIZE_PART_BOOT+101MB)" |
        sed -e 's/KB/\*1024/g' -e 's/MB/\*1048576/g' -e 's/GB/\*1073741824/g' | bc)

    # Create empty image file of calculated size to represent output disk
    truncate --size "$SIZE_IMAGE" "$PATH_IMG_OUT"
}

# Function to handle the GET_QUOTE boot mode
function handle_get_quote() {
    echo "=============== Cleanup Last Run ==============="

    cleanup_get_quote "$PATH_IMG_IN"

    echo "=============== Create Empty Image ==============="

    # If not set per parameter, set size of rootfs partition and boot partition to default values.
    SIZE_PART_ROOTFS=${SIZE_PART_ROOTFS:-10GB}
    SIZE_PART_BOOT=${SIZE_PART_BOOT:-2GB}

    # Create an empty image
    create_image "$SIZE_PART_ROOTFS" "$SIZE_PART_BOOT" "$PATH_IMG_OUT"

    echo "=============== Create Image Partitions ==============="

    # Create partitions
    IFS='|' read -r LOOPDEV PART_EFI PART_BOOT PART_ROOTFS <<< "$(create_partitions "$SIZE_PART_BOOT" "$PATH_IMG_OUT" | tail -n 1)"
    echo -e "LOOPDEV:${LOOPDEV} \nROOT:${PART_ROOTFS} \nEFI:${PART_EFI} \nBOOT:${PART_BOOT}"

    echo "=============== Encrypt RootFS and Open =========="

    # Encrypt root partition with LUKS and open the partition to a virtual device.
    # Provided Root file system key is used for the encryption.
    DEV_ROOTFS_DEC=$(create_luks_partition  "$PART_ROOTFS" "$LABEL_PART_ROOTFS_ENC" "$LABEL_DEV_ROOTFS_DEC" "$K_RFS_HEX" | tail -n 1)
    echo "Virtual device providing decrypted access to encrypted root partition: $DEV_ROOTFS_DEC"

    echo "=============== Format Partitions =========="

    format_partitions "$PART_EFI" "$PART_BOOT" "$DEV_ROOTFS_DEC"
    echo "Formatting done"

    echo "=============== Fill Opened RootFS ========"

    # Fill RootFS with needed files
    fill_rootfs "$PART_EFI" "$PART_BOOT" "$DEV_ROOTFS_DEC" "$PART_ROOTFS" "$PATH_IMG_IN" "$KBS_CERT_PATH" "$LABEL_PART_ROOTFS_ENC" "$LABEL_DEV_ROOTFS_DEC"

    echo "=============== Close Partitions ============="

    # Deactivate partitions
    close_partitions "$DEV_ROOTFS_DEC" "$LOOPDEV"

    echo "=============== Enroll Variables into OVMF ============="

    # Enroll variables in OVMF
    modify_ovmf
}

# Function to perform cleanup when script is interrupted
function cleanup_on_interrupt() {
    echo "=============== Script interrupted - Cleaning up resources ==============="

    # cleanup function
    cleanup_get_quote "$PATH_IMG_IN"

    echo "=============== Cleanup completed ==============="
}

set -e

process_args "$@"

echo "=============== Build Start ==============="
echo "=============== Check Validity of Parameters ==============="

check_args_env

# Setup trap to catch interruptions
trap cleanup_on_interrupt SIGINT SIGTERM 

OVMF_INPUT="${MY_PATH}/../../data/ovmf-extracted/usr/share/ovmf/OVMF.tdx.fd"
OVMF_OUTPUT="OVMF_FDE.fd"

# Main script execution
handle_get_quote "$@"

echo "=============== Set Owner of Created OVMF and TD Image ============="
USER_GROUP=$(id -gn "$LOGIN_USER")
chown "$LOGIN_USER":"$USER_GROUP" "$OVMF_OUTPUT"
chown "$LOGIN_USER":"$USER_GROUP" "$PATH_IMG_OUT"

# Output full paths of the created files
echo "=============== Created Files ================"
echo "OVMF_PATH: $(realpath "$OVMF_OUTPUT")"
echo "IMAGE_PATH: $(realpath "$PATH_IMG_OUT")"

echo "=============== Build End ================"

popd
