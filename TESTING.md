# Scripts 1+2 - Testing Guide


### Testing on EC2 Instance

#### Prerequisites

1. Launch an EC2 instance
2. Ensure instance has proper IAM role/permissions
3. Security group allows SSH access
4. You have SSH key pair for initial access

#### Step 1: Copy Files to Instance

```bash
# From your local machine
scp -i your-key.pem eic_run.py ec2-user@instance-ip:/tmp/
scp -i your-key.pem eic_curl.py ec2-user@instance-ip:/tmp/
```

#### Step 2: Install Files on Instance

```bash
# SSH into instance
ssh -i your-key.pem ec2-user@instance-ip

# Install files
sudo chmod 755 /usr/tmp/eic_curl.py
sudo chmod 755 /usr/tmp/eic_run.py
```

#### Step 3: Test eic_curl Directly (No Keys Scenario)

Test the script when no SSH keys have been pushed:

```bash
sudo /usr/tmp/eic_curl.py ec2-user
```

**Expected behavior**:
- Script should exit with code 0
- Should log "HTTP error 404 while checking for active keys"
- This is **correct behavior** - HTTP 404 means no keys are available

#### Step 4: Test eic_run Wrapper

```bash
sudo /usr/tmp/eic_run.py ec2-user
```

**Expected output**:
- Same as above (calls eic_curl.py internally)

#### Step 5: Test with AWS-Pushed Keys

From your **local machine**, push a temporary SSH key to the instance:

```bash
# Generate a temporary SSH key (or use existing one)
ssh-keygen -t rsa -f /tmp/temp-ec2-key -N ""

# Push the public key to the instance
aws ec2-instance-connect send-ssh-public-key \
    --instance-id i-XXXXXXXXXXXXXXXXX \
    --instance-os-user ec2-user \
    --ssh-public-key file:///tmp/temp-ec2-key.pub \
    --availability-zone us-east-1a
```

Then on the **EC2 instance**, run the script again:

```bash
sudo /usr/tmp/eic_run.py ec2-user
```

**Expected output**:
```
LOG: Checking for username argument
Username: ec2-user
LOG: Verifying username
LOG: Fetching token from IMDS
Token: AQAEAA0U2e3CShezzEgt0g9aQgCTELDO8qg4ekj-NBeekUp8rML2ag==
LOG: Fetching instance ID
Instance ID: i-0b9438c1e51396080
LOG: Verifying instance ID
Instance ID verified
LOG: Verifying EC2 instance
Nitro instance detected
Board asset tag: i-0b9438c1e51396080
Instance verified
LOG: Checking active keys
Active keys found
LOG: Validating the AZ
AZ: us-east-1a
Region: us-east-1
LOG: Validating region and domain
Domain: amazonaws.com
LOG: Fetching signer certificate
Signer: managed-ssh-signer.us-east-1.amazonaws.com
Userpath: /dev/shm/eic-XXXXXX
Cert: Fetched XXXX bytes
LOG: Fetching OCSP staples
OCSP path: /dev/shm/eic-XXXXXX/eic-ocsp-XXXXXX
LOG: Fetching SSH keys
Keys file: /dev/shm/eic-XXXXXX/eic-keys
LOG: Calling parsing script
(Parser output will appear here)
```