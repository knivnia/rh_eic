## Connecting to EC2 Instance with bare scripts (pre-packaging)

  1. Copy scripts to the instance
  
  `scp -i <key.pem> eic_run.py eic_curl.py eic_parse.py ec2-user@<ip>:/tmp/`

  2. Install scripts to a proper location (sshd rejects /tmp)
  
  `sudo mkdir -p /opt/aws/bin`
  
  `sudo cp /tmp/*.py /opt/aws/bin/`
 
  `sudo chown root:root /opt/aws/bin/*.py`
  
  `sudo chmod 755 /opt/aws/bin/*.py`

  3. Configure sshd
  
  ```
  sudo bash -c 'cat > /etc/ssh/sshd_config.d/60-eic.conf << EOF
  AuthorizedKeysCommand /opt/aws/bin/eic_run.py %u %f
  AuthorizedKeysCommandUser root
  EOF'
  ```
 
  `sudo chmod 600 /etc/ssh/sshd_config.d/60-eic.conf`
  
  `sudo sshd -t && sudo systemctl restart sshd`

  4. Fix SELinux (collect all denials in one pass)
  
  `sudo setenforce 0`
  Connect via web UI once (this generates all SELinux denials), then:
  
  `sudo ausearch -m avc | sudo audit2allow -M eic_sshd`
  
  `sudo semodule -i eic_sshd.pp`
  
  `sudo setenforce 1`

  5. Verify
  
  `sudo sshd -T | grep -i authorizedkeyscommand`
  
  `getenforce  # should say "Enforcing"`
