#!/bin/bash
set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }
log_step() { echo -e "${BLUE}[STEP]${NC} $1"; }

error_exit() {
    log_error "$1"
    exit 1
}

cleanup_on_error() {
    log_warn "Cleaning up failed deployment..."
    docker stop trustee-vault trustee-as trustee-kbs 2>/dev/null || true
    docker rm trustee-vault trustee-as trustee-kbs 2>/dev/null || true
}

trap cleanup_on_error ERR

# Check if this is a restart scenario
if [ -f "config-data/env.sh" ] \
    && [ -f "config-data/tls-cert.pem" ] \
    && [ -f "config-data/auth-private.key" ] \
    && [ -f "config-data/auth-public.pub" ] \
    && docker ps -a --format "{{.Names}}" | grep -q "^trustee-vault$" \
    && docker ps -a --format "{{.Names}}" | grep -q "^trustee-as$" \
    && docker ps -a --format "{{.Names}}" | grep -q "^trustee-kbs$"
then
    echo ""
    echo "=========================================="
    echo "  Detected existing Trustee installation"
    echo "=========================================="
    echo ""
    
    read -p "Do you want to restart existing containers instead of full setup? (Y/n) " -n 1 -r
    echo
    if [[ "$REPLY" =~ ^[Yy]$|^$ ]]; then
        log_info "Restarting existing Trustee deployment..."
        
        # Create network if it doesn't exist
        docker network create trustee-net 2>/dev/null && log_info "Network created" || log_warn "Network already exists"

        # Check port 8200 (Vault)
        if VAULT_PID=$(lsof -Pi :8200 -sTCP:LISTEN -t 2>/dev/null); then
            VAULT_PROCESS=$(ps -p "$VAULT_PID" -o comm= 2>/dev/null)
            log_error "Port 8200 is in use by PID $VAULT_PID ($VAULT_PROCESS)"
            error_exit "Please free port 8200 to setup Vault service."
        fi

        # Check port 50004 (Attestation Service)
        if AS_PID=$(lsof -Pi :50004 -sTCP:LISTEN -t 2>/dev/null); then
            AS_PROCESS=$(ps -p "$AS_PID" -o comm= 2>/dev/null)
            log_error "Port 50004 is in use by PID $AS_PID ($AS_PROCESS)"
            error_exit "Please free port 50004 to setup Attestation Service."
        fi

        # Check port 8080 (KBS)
        if KBS_PID=$(lsof -Pi :8080 -sTCP:LISTEN -t 2>/dev/null); then
            KBS_PROCESS=$(ps -p "$KBS_PID" -o comm= 2>/dev/null)
            log_error "Port 8080 is in use by PID $KBS_PID ($KBS_PROCESS)"
            error_exit "Please free port 8080 to setup Key Broker Service."
        fi
        
        # Start containers
        for container in trustee-vault trustee-as trustee-kbs; do
            if docker ps -a --format "{{.Names}}" | grep -q "^${container}$"; then
                if ! docker ps --format "{{.Names}}" | grep -q "^${container}$"; then
                    docker start $container && log_info "$container started"
                else
                    log_info "$container already running"
                fi
            else
                log_warn "$container not found - run full setup instead"
                exit 1
            fi
        done
        
        # Load environment
        source config-data/env.sh
        
        echo ""
        echo "Services are running:"
        docker ps --filter name=trustee --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}"
        log_info "Trustee deployment restarted successfully."
        exit 0
    fi
fi

# Check if in trustee directory
if [ ! -d "kbs" ] || [ ! -d "attestation-service" ]; then
    error_exit "Run this script from trustee repository root directory"
fi

log_info "Checking for required files..."

# Check if Vault token is set
if [ -z "$VAULT_ROOT_TOKEN" ]; then
    error_exit "VAULT_ROOT_TOKEN not set. Please run: export VAULT_ROOT_TOKEN=\$(openssl rand -hex 16)"
fi

# Check if certificates exist
if [ ! -f "config-data/tls-cert.pem" ] || [ ! -f "config-data/tls-key.pem" ]; then
    error_exit "TLS certificates not found in config-data/. Please generate them first following the README instructions."
fi

# Check if auth keys exist
if [ ! -f "config-data/auth-private.key" ] || [ ! -f "config-data/auth-public.pub" ]; then
    error_exit "Authentication keys not found in config-data/. Please generate them first following the README instructions."
fi

# Stop and remove existing containers if running
log_info "Checking for existing Trustee containers..."
existing_containers=$(docker ps -a --filter name=trustee --format "{{.Names}}" 2>/dev/null)

if [ -n "$existing_containers" ]; then
    log_warn "Removing existing Trustee containers..."
    echo "$existing_containers" | while read container; do
        docker stop "$container" 2>/dev/null && log_info "Stopped $container"
        docker rm "$container" 2>/dev/null && log_info "Removed $container"
    done
fi

# Check port 8200 (Vault)
if VAULT_PID=$(lsof -Pi :8200 -sTCP:LISTEN -t 2>/dev/null); then
    VAULT_PROCESS=$(ps -p "$VAULT_PID" -o comm= 2>/dev/null)
    log_error "Port 8200 is in use by PID $VAULT_PID ($VAULT_PROCESS)"
    error_exit "Please free port 8200 to setup Vault service."
fi

# Check port 50004 (Attestation Service)
if AS_PID=$(lsof -Pi :50004 -sTCP:LISTEN -t 2>/dev/null); then
    AS_PROCESS=$(ps -p "$AS_PID" -o comm= 2>/dev/null)
    log_error "Port 50004 is in use by PID $AS_PID ($AS_PROCESS)"
    error_exit "Please free port 50004 to setup Attestation Service."
fi

# Check port 8080 (KBS)
if KBS_PID=$(lsof -Pi :8080 -sTCP:LISTEN -t 2>/dev/null); then
    KBS_PROCESS=$(ps -p "$KBS_PID" -o comm= 2>/dev/null)
    log_error "Port 8080 is in use by PID $KBS_PID ($KBS_PROCESS)"
    error_exit "Please free port 8080 to setup Key Broker Service."
fi

log_info "All prerequisites verified"

# Configure proxy settings (inherit from environment or use defaults)
export http_proxy=${http_proxy:-}
export https_proxy=${https_proxy:-}
export no_proxy=${no_proxy:-}
export HTTP_PROXY=${HTTP_PROXY:-$http_proxy}
export HTTPS_PROXY=${HTTPS_PROXY:-$https_proxy}
export NO_PROXY=${NO_PROXY:-$no_proxy}

# Add Docker network to no_proxy
if [ -n "$no_proxy" ]; then
    export no_proxy="${no_proxy},trustee-vault,trustee-as,trustee-kbs"
    export NO_PROXY="${NO_PROXY},trustee-vault,trustee-as,trustee-kbs"
else
    export no_proxy="localhost,127.0.0.1,trustee-vault,trustee-as,trustee-kbs"
    export NO_PROXY="localhost,127.0.0.1,trustee-vault,trustee-as,trustee-kbs"
fi

echo ""
echo "=========================================="
echo "  Trustee Deployment Setup"
echo "=========================================="
echo ""

# ============================================
# Step 1: Apply KBS Patch
# ============================================
log_step "Step 1: Applying KBS patch to KBS Dockerfile"

if [ ! -f "trustee-kbs.patch" ]; then
    error_exit "trustee-kbs.patch not found. Please create it first."
fi

# Check if patch is already applied
if grep -q "make background-check-kbs VAULT=true" kbs/docker/coco-as-grpc/Dockerfile; then
    log_warn "KBS patch already applied"
else
    # Apply patch
    if git apply --check trustee-kbs.patch 2>/dev/null; then
        git apply trustee-kbs.patch
        log_info "KBS patch applied successfully"
    else
        error_exit "Failed to apply patch. Check trustee-kbs.patch file"
    fi
fi

# ============================================
# Step 2: Build Docker Images
# ============================================
log_step "Step 2: Building Docker images"

log_info "Building Attestation Service image..."
if ! docker build \
    --build-arg http_proxy=$http_proxy \
    --build-arg https_proxy=$https_proxy \
    --build-arg no_proxy=$no_proxy \
    --ulimit nofile=90000:90000 \
    -f attestation-service/docker/as-grpc/Dockerfile \
    -t trustee-as:latest . 2>&1 | tee /tmp/as-build.log; then
    log_error "Attestation Service build failed. Build log:"
    tail -n 50 /tmp/as-build.log
    error_exit "Failed to build Attestation Service"
fi

log_info "Attestation Service image built successfully"

log_info "Building KBS image with Vault support..."
if ! docker build \
    --build-arg http_proxy=$http_proxy \
    --build-arg https_proxy=$https_proxy \
    --build-arg no_proxy=$no_proxy \
    --ulimit nofile=90000:90000 \
    -f kbs/docker/coco-as-grpc/Dockerfile \
    -t trustee-kbs:latest . 2>&1 | tee /tmp/kbs-build.log; then
    log_error "KBS build failed. Build log:"
    tail -n 50 /tmp/kbs-build.log
    error_exit "Failed to build KBS"
fi

log_info "KBS image built successfully"

# ============================================
# Step 3: Create Docker Network
# ============================================
log_step "Step 3: Creating Docker network"

if docker network create trustee-net 2>/dev/null; then
    log_info "Docker network created"
else
    log_warn "Docker network already exists"
fi

# ============================================
# Step 4: Start Vault
# ============================================
log_step "Step 4: Starting Vault container"

docker run -d \
    --name trustee-vault \
    --network trustee-net \
    --restart unless-stopped \
    -p 8200:8200 \
    -e VAULT_DEV_ROOT_TOKEN_ID="$VAULT_ROOT_TOKEN" \
    -e VAULT_DEV_LISTEN_ADDRESS=0.0.0.0:8200 \
    -e no_proxy=$no_proxy \
    -e https_proxy=$https_proxy \
    -e http_proxy=$http_proxy \
    -e NO_PROXY=$NO_PROXY \
    -e HTTPS_PROXY=$HTTPS_PROXY \
    -e HTTP_PROXY=$HTTP_PROXY \
    --cap-add=IPC_LOCK \
    hashicorp/vault:1.20 > /dev/null 2>&1 || error_exit "Failed to start Vault container"

log_info "Vault container started"
log_info "Waiting for Vault to initialize..."

# Wait for Vault to be ready
MAX_RETRIES=30
RETRY_COUNT=0

while [ $RETRY_COUNT -lt $MAX_RETRIES ]; do
    if docker exec -e VAULT_ADDR='http://127.0.0.1:8200' trustee-vault vault status >/dev/null 2>&1; then
        VAULT_READY=true
        break
    fi
    RETRY_COUNT=$((RETRY_COUNT + 1))
    sleep 1
done

if [ "$VAULT_READY" = false ]; then
    log_error "Vault failed to initialize after ${MAX_RETRIES} seconds"
    docker logs trustee-vault
    error_exit "Vault initialization timeout"
fi

log_info "Vault is ready"

# ============================================
# Step 5: Configure Vault
# ============================================
log_step "Step 5: Configuring Vault"

log_info "Enabling KV secrets engine..."
docker exec -e VAULT_ADDR='http://127.0.0.1:8200' -e VAULT_TOKEN="$VAULT_ROOT_TOKEN" \
    trustee-vault vault secrets enable -version=1 -path=keybroker kv > /dev/null 2>&1 || error_exit "Failed to enable KV secrets engine"

log_info "KV secrets engine enabled at path: keybroker"

# ============================================
# Step 6: Create Configuration Files
# ============================================
log_step "Step 6: Creating configuration files"

export SYSTEM_IP=$(hostname -I | awk '{print $1}')
log_info "Detected system IP: $SYSTEM_IP"

log_info "Creating Attestation Service configuration..."
cat > config-data/as-config.json <<'EOF'
{
    "policy_engine": "opa",
    "rvps_config": {
        "type": "BuiltIn",
        "storage": {
            "type": "LocalFs",
            "file_path": "/opt/attestation-service/reference-values"
        }
    },
    "attestation_token_broker": {
        "type": "Simple",
        "duration_min": 5
    }
}
EOF

mkdir -p config-data/reference-values/

log_info "Creating KBS configuration..."
cat > config-data/kbs-config.toml <<EOF
[http_server]
sockets = ["0.0.0.0:8080"]
private_key = "/opt/kbs/certs/tls-key.pem"
certificate = "/opt/kbs/certs/tls-cert.pem"
insecure_http = false

[attestation_token]
insecure_key = true

[attestation_service]
type = "coco_as_grpc"
as_addr = "http://trustee-as:50004"
policy_engine = "opa"

[attestation_service.attestation_token_broker]
type = "Ear"
duration_min = 5

[attestation_service.rvps_config]
type = "BuiltIn"

[admin]
auth_public_key = "/opt/kbs/certs/auth-public.pub"

[[plugins]]
name = "resource"
type = "Vault"
vault_url = "http://trustee-vault:8200"
token = "$VAULT_ROOT_TOKEN"
mount_path = "keybroker"
kv_version = 1
EOF

log_info "Configuration files created successfully"

# ============================================
# Step 7: Start Attestation Service
# ============================================
log_step "Step 7: Starting Attestation Service"

docker run -d \
    --name trustee-as \
    --network trustee-net \
    --restart unless-stopped \
    -p 50004:50004 \
    -v $(pwd)/config-data/as-config.json:/opt/attestation-service/config.json:ro \
    -v $(pwd)/config-data/reference-values:/opt/attestation-service/reference-values \
    -v $(pwd)/attestation-service/docs/sgx_default_qcnl.conf:/etc/sgx_default_qcnl.conf:ro \
    -e RUST_LOG=debug \
    -e no_proxy=$no_proxy \
    -e https_proxy=$https_proxy \
    -e http_proxy=$http_proxy \
    -e NO_PROXY=$NO_PROXY \
    -e HTTPS_PROXY=$HTTPS_PROXY \
    -e HTTP_PROXY=$HTTP_PROXY \
    trustee-as:latest \
    grpc-as --config-file /opt/attestation-service/config.json --socket 0.0.0.0:50004 > /dev/null 2>&1 || error_exit "Failed to start Attestation Service"

log_info "Attestation Service container started"
log_info "Waiting for Attestation Service to initialize..."
sleep 3

if ! docker ps | grep -q trustee-as; then
    error_exit "Attestation Service failed to start. Check logs with: docker logs trustee-as"
fi

log_info "Attestation Service is running"

# ============================================
# Step 8: Start KBS
# ============================================
log_step "Step 8: Starting Key Broker Service"

docker run -d \
    --name trustee-kbs \
    --network trustee-net \
    --restart unless-stopped \
    -p 8080:8080 \
    -v $(pwd)/config-data/kbs-config.toml:/opt/kbs/kbs-config.toml:ro \
    -v $(pwd)/config-data/tls-cert.pem:/opt/kbs/certs/tls-cert.pem:ro \
    -v $(pwd)/config-data/tls-key.pem:/opt/kbs/certs/tls-key.pem:ro \
    -v $(pwd)/config-data/auth-public.pub:/opt/kbs/certs/auth-public.pub:ro \
    -e RUST_LOG=debug \
    -e no_proxy=$no_proxy \
    -e https_proxy=$https_proxy \
    -e http_proxy=$http_proxy \
    -e NO_PROXY=$NO_PROXY \
    -e HTTPS_PROXY=$HTTPS_PROXY \
    -e HTTP_PROXY=$HTTP_PROXY \
    trustee-kbs:latest \
    kbs --config-file /opt/kbs/kbs-config.toml > /dev/null 2>&1 || error_exit "Failed to start KBS"

log_info "KBS container started"
log_info "Waiting for KBS to initialize..."
sleep 3

if ! docker ps | grep -q trustee-kbs; then
    error_exit "KBS failed to start. Check logs with: docker logs trustee-kbs"
fi

log_info "KBS is running"

# ============================================
# Step 9: Save Environment Variables
# ============================================
log_step "Step 9: Saving environment variables"

cat > config-data/env.sh <<EOF
#!/bin/bash
# Trustee Environment Variables
# Usage: source config-data/env.sh

export SYSTEM_IP="$SYSTEM_IP"
export KBS_URL="https://\$SYSTEM_IP:8080"
export KBS_CERT_PATH="\$(pwd)/config-data/tls-cert.pem"
export AUTH_PRIVATE_KEY="\$(pwd)/config-data/auth-private.key"
export VAULT_ADDR="http://\$SYSTEM_IP:8200"
export VAULT_ROOT_TOKEN="$VAULT_ROOT_TOKEN"
EOF

chmod +x config-data/env.sh
log_info "Environment variables saved to config-data/env.sh"

# ============================================
# Step 10: Verify Deployment
# ============================================
log_step "Step 10: Verifying deployment"

log_info "Checking container status..."
RUNNING_CONTAINERS=$(docker ps --filter name=trustee --format "{{.Names}}" | wc -l)

if [ "$RUNNING_CONTAINERS" -eq 3 ]; then
    log_info "All containers are running"
else
    log_warn "Expected 3 containers, found $RUNNING_CONTAINERS running"
fi

# ============================================
# Summary
# ============================================
echo ""
echo "=========================================="
log_info "Trustee Deployment Complete"
echo "=========================================="
echo ""
echo "Services:"
echo "  KBS:   https://$SYSTEM_IP:8080"
echo "  AS:    grpc://$SYSTEM_IP:50004"
echo "  Vault: http://$SYSTEM_IP:8200"
echo ""
echo ""
echo "Environment Variables:"
echo "  KBS_URL:           https://$SYSTEM_IP:8080"
echo "  KBS_CERT_PATH:     $(pwd)/config-data/tls-cert.pem"
echo "  AUTH_PRIVATE_KEY:  $(pwd)/config-data/auth-private.key"
echo ""
echo "Usage:"
echo "  Load environment:  source config-data/env.sh"
echo "  View KBS logs:     docker logs -f trustee-kbs"
echo "  View AS logs:      docker logs -f trustee-as"
echo "  View Vault logs:   docker logs -f trustee-vault"
echo "  Check status:      docker ps --filter name=trustee"
echo ""