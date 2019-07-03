catalog app

# Catalog App

### Getting Started
This will instruction will get you running this project and produce the same result on your local machine. This instruction works on a Mac or Linux platform.

### What it does
* View existing categories, their items, item's detail.
* User can log in to the app with their google account to have new/edit/delete access.

### Prerequisites
* Vagrant.
* VirtualBox.
* A virtual machine downloaded online with python3 environment.
* Project files in the repo.

### Installing
* Install Vagrant: https://www.vagrantup.com/downloads.html.
* Install VirtualBox: https://www.virtualbox.org/wiki/Download_Old_Builds_5_1.
* Clone the repo: [GitHub - knightcnbj/fullstack-nanodegree-vm].(https://github.com/knightcnbj/fullstack-nanodegree-vm.git).

### Getting started
* After clone the repo, unzip it, go to /vagrant directory, run ```vagrant up``` to boot the vm, then ```vagrant ssh``` to login.
* In the VM, go to ```/vagrant``` directory, this is mapping to the ```fullstack-nanodegree-vm/vagrant/``` on your local machine. Run ```python database_setup``` to initialize the database. Then run ```python adding_items_cate``` to add example categories and items into the databaase.
* Run ```python application.py```, go to ```localhost:8000``` in your browser (suggesting chrome or firefox)

## Authors
* **Lu Mao**