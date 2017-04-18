# -*- mode: ruby -*-
# vi: set ft=ruby :

Vagrant.configure(2) do |config|
  config.vm.box = "ubuntu/trusty64"

  config.vm.synced_folder ".", "/home/vagrant/lxc"

  config.vm.provision "shell", inline: <<-SHELL
    sudo add-apt-repository ppa:ubuntu-lxc/daily -y
    sudo apt-get update -qq
    sudo apt-get install -qq gcc automake
    sudo apt-get install -qq libapparmor-dev libcap-dev libseccomp-dev python3-dev docbook2x libgnutls-dev liblua5.2-dev libselinux1-dev libcgmanager-dev
  SHELL
end
