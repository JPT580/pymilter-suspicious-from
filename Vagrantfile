# -*- mode: ruby -*-
# vi: set ft=ruby :

Vagrant.configure("2") do |config|
  config.vm.box = "debian/buster64"

  config.vm.synced_folder "./", "/vagrant", type: "rsync"

  # Export postfix port 25 (guest) to port 2525 (host)
  # This is useful for throwing swaks and other tools against postfix
  config.vm.network "forwarded_port", guest: 7777, host: 7777

  config.vm.provision "shell", inline: <<-SHELL
    # Give that vagrant box an apparently good FQDN
    echo "local-vagrant.example.com" > /etc/hostname
    echo "local-vagrant.example.com" > /etc/mailname
    echo "127.0.1.2 local-vagrant.example.com local-vagrant" > /etc/hosts
    hostnamectl set-hostname local-vagrant.example.com

    # Basic preparations
    apt-get update

    # Install postfix
    DEBIAN_FRONTEND=noninteractive apt-get install -y postfix

    # Add milter to configuration
    postconf smtpd_milters=inet:127.0.0.1:7777
    postconf non_smtpd_milters=inet:127.0.0.1:7777

    # Enable and launch postfix
    systemctl enable postfix.service
    systemctl start postfix.service

    # Install swaks
    DEBIAN_FRONTEND=noninteractive apt-get install -y swaks


    # Install required dependencies
    DEBIAN_FRONTEND=noninteractive apt-get install -y python3-venv build-essential python3-dev python3-wheel libmilter-dev

    # Create virtualenv for project
    sudo -u vagrant python3 -m venv /tmp/venv
    sudo -u vagrant /tmp/venv/bin/pip install -r /vagrant/requirements.txt

    echo "Fireing it up ..."
    sudo -u vagrant /tmp/venv/bin/python /vagrant/main.py

  SHELL

  config.trigger.after :up do |t|
    t.info = "rsync"
    t.run = {inline: "vagrant rsync"}
    # If you want it running in the background switch these
    #t.run = {inline: "bash -c 'vagrant rsync-auto bork &'"}
  end

end
