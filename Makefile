# VAR — Verifiable Agent Runtime
# ──────────────────────────────────────────────────────────────────────────────
# Targets
#   build           zig build (produces zig-out/bin/VAR and zig-out/bin/VAR-gateway)
#   build-eif       build Docker image and package into an Enclave Image File
#   create-ecr      create the ECR repository (idempotent; run once before push-ecr)
#   push-ecr        push the Docker image to ECR (requires AWS credentials)
#   run             start the enclave (requires nitro-cli and an EIF)
#   stop            terminate the running enclave
#   logs            stream the enclave console
#   pcr0            print the PCR0 measurement of the EIF (use after build-eif)
#   install-proxy   install the KMS proxy on the host instance (sudo required)
#   test            run Zig unit tests + Python pytest suites
#   clean           remove build artefacts and the EIF

# ──────────────────────────────────────────────────────────────────────────────
# Configurable variables (override on the command line or in the environment)
# ──────────────────────────────────────────────────────────────────────────────
AWS_ACCOUNT_ID    ?= $(shell aws sts get-caller-identity --query Account --output text 2>/dev/null)
AWS_DEFAULT_REGION ?= us-east-1
ECR_REPO          ?= $(AWS_ACCOUNT_ID).dkr.ecr.$(AWS_DEFAULT_REGION).amazonaws.com/var-enclave
IMAGE_TAG         ?= latest

# nitro-cli enclave configuration
ENCLAVE_CID    ?= 16
ENCLAVE_MEMORY ?= 512
ENCLAVE_CPUS   ?= 2
EIF_PATH       ?= var.eif

# ──────────────────────────────────────────────────────────────────────────────
.PHONY: all build build-eif create-ecr push-ecr run stop logs pcr0 install-proxy test clean

all: build

# 1. Build Zig binaries
build:
	zig build -Doptimize=ReleaseSafe

# 2. Build EIF (requires Docker + nitro-cli on the build host)
build-eif:
	docker build -t var-enclave:$(IMAGE_TAG) .
	nitro-cli build-enclave \
	  --docker-uri   var-enclave:$(IMAGE_TAG) \
	  --output-file  $(EIF_PATH)
	@echo ""
	@echo "EIF written to $(EIF_PATH).  PCR0:"
	@$(MAKE) --no-print-directory pcr0

# 3a. Create the ECR repository (idempotent — safe to run if it already exists)
create-ecr:
	aws ecr create-repository \
	  --repository-name var-enclave \
	  --region $(AWS_DEFAULT_REGION) \
	  --image-scanning-configuration scanOnPush=true \
	  --encryption-configuration encryptionType=AES256 \
	  2>&1 | grep -v "RepositoryAlreadyExistsException" || true
	@echo "ECR repository ready: $(ECR_REPO)"

# 3b. Push Docker image to ECR (run create-ecr first if the repo does not exist)
push-ecr:
	aws ecr get-login-password --region $(AWS_DEFAULT_REGION) \
	  | docker login --username AWS --password-stdin $(ECR_REPO)
	docker tag  var-enclave:$(IMAGE_TAG) $(ECR_REPO):$(IMAGE_TAG)
	docker push $(ECR_REPO):$(IMAGE_TAG)

# 4. Launch the enclave
run:
	nitro-cli run-enclave \
	  --enclave-cid  $(ENCLAVE_CID) \
	  --memory       $(ENCLAVE_MEMORY) \
	  --cpu-count    $(ENCLAVE_CPUS) \
	  --eif-path     $(EIF_PATH)

# 5. Terminate the running enclave (first one returned by describe-enclaves)
stop:
	nitro-cli terminate-enclave \
	  --enclave-id $$(nitro-cli describe-enclaves | jq -r '.[0].EnclaveID')

# 6. Stream the enclave console (Ctrl-C to detach)
logs:
	nitro-cli console \
	  --enclave-id $$(nitro-cli describe-enclaves | jq -r '.[0].EnclaveID')

# 7. Print the PCR0 measurement (use this value in the KMS key policy)
pcr0:
	@nitro-cli describe-eif --eif-path $(EIF_PATH) | jq -r '.Measurements.PCR0'

# 8. Install the KMS proxy service on the parent EC2 instance (requires sudo)
install-proxy:
	sudo mkdir -p /opt/var
	sudo cp src/host/proxy.py src/host/requirements.txt /opt/var/
	sudo pip3 install --quiet -r /opt/var/requirements.txt
	sudo useradd --system --no-create-home var-proxy 2>/dev/null || true
	sudo cp src/host/var-kms-proxy.service /etc/systemd/system/
	sudo systemctl daemon-reload
	sudo systemctl enable --now var-kms-proxy
	@echo "var-kms-proxy installed and started."
	@echo "Set VAR_KMS_KEY_ARN in /etc/systemd/system/var-kms-proxy.service.d/override.conf"

# 9. Run all tests (Zig unit tests + Python pytest suites)
test:
	zig build test
	pytest src/host/tests/ src/agent/tests/ tests/ -v

# 10. Remove build artefacts
clean:
	rm -rf zig-out zig-cache .zig-cache $(EIF_PATH)
