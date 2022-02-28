![PWN](https://github.com/0dayinc/pwn/blob/master/documentation/pwn_wallpaper.jpg)

### **Table of Contents** ###
- [Keep Us Caffeinated](#keep-us-caffeinated)
- [Call to Arms](#call-to-arms)
- [Intro](#intro)
  * [Why PWN](#why-pwn)
  * [How PWN Works](#how-pwn-works)
  * [What is PWN](#what-is-pwn)
  * [PWN Modules Can be Mixed and Matched to Produce Your Own Tools](#pwn-modules-can-be-mixed-and-matched-to-produce-your-own-tools)
  * [Creating an OWASP ZAP Scanning Driver Leveraging the pwn Prototyper](#creating-an-owasp-zap-scanning-driver-leveraging-the-pwn-prototyper)
- [Clone PWN](#clone-pwn)
- [Deploy](#deploy)
  * [Basic Installation Dependencies](#basic-installation-dependencies)
  * [Install Locally on Host OS](#install-locally-on-host-os)
  * [Deploy in AWS EC2](#deploy-in-aws-ec2)
  * [Deploy in Docker Container](#deploy-in-docker-container)
  * [Deploy in VirtualBox](#deploy-in-virtualbox)
  * [Deploy in VMware](#deploy-in-vmware)
  * [Deploy in vSphere](#deploy-in-vsphere)
- [General Usage](#general-usage)
- [Driver Documentation](#driver-documentation)
- [Merchandise](#merchandise)


### **Keep Us Caffeinated** ###
If you've found this framework useful and you're either not in a position to donate or simply interested in us cranking out as many features as possible, we invite you to take a brief moment to keep us caffeinated:

[![Coffee](https://www.buymeacoffee.com/assets/img/custom_images/orange_img.png)](https://buymeacoff.ee/0dayinc)

### **Call to Arms** ###
If you're willing to provide access to commercial security tools (e.g. Rapid7's Nexpose, Tenable Nessus, QualysGuard, HP WebInspect, IBM Appscan, etc) please PM us as this will continue to promote PWNs interoperability w/ industry-recognized security tools moving forward.  Additionally if you want to contribute to this framework's success, check out our [How to Contribute](https://github.com/0dayInc/pwn/blob/master/CONTRIBUTING.md).  Lastly, we accept [donations](https://cash.me/$fundpwn).


### **Intro** ###
#### **What is PWN** ####
PWN (Continuous Security Integration) is an open security automation framework that aims to stand on the shoulders of security giants, promoting trust and innovation.  Build your own custom automation drivers freely and easily using pre-built modules.  If a picture is worth a thousand words, then a video must be worth at least a million...let's begin by planting a million seeds in your mind:

#### **Creating an OWASP ZAP Scanning Driver Leveraging the pwn Prototyper** ####
[![Continuous Security Integration: Basics of Building Your Own Security Automation ](https://i.ytimg.com/vi/MLSqd5F-Bjw/0.jpg)](https://youtu.be/MLSqd5F-Bjw)

#### **Why PWN** ####
It's easy to agree that while corporate automation is a collection of proprietary source code, the core modules used to produce automated solutions should be open for all eyes to continuously promote trust and innovation...broad collaboration is key to any automation framework's success, particularly in the cyber security arena.  

#### **How PWN Works** ####
Leveraging various pre-built modules and the pwn prototyper, you can mix-and-match modules to test, record, replay, and rollout your own custom security automation packages known as, "drivers."  

#### **PWN Modules Can be Mixed and Matched to Produce Your Own Tools** ####
Also known as, "Drivers" PWN can produce all sorts of useful tools by mixing and matching modules.
![PWN](https://github.com/0dayinc/pwn/blob/master/documentation/PWN_Driver_Arch.png)



### **Clone PWN** ###
Certain Constraints Mandate PWN be Installed in /opt/pwn:
 `$ sudo git clone https://github.com/0dayinc/pwn.git /opt/pwn`



### **Deploy** ###
#### **Basic Installation Dependencies** ###
- Latest Version of Vagrant: https://www.vagrantup.com/downloads.html
- Latest Version of Vagrant VMware Utility (if using VMware): https://www.vagrantup.com/vmware/downloads.html
- Packer: https://www.packer.io/downloads.html (If you contribute to the Kali Rolling Box hosted on https://app.vagrantup.com/pwn/boxes/kali_rolling)

#### **Install Locally on Host OS** ####
[Instructions](https://gist.github.com/ninp0/613696fbf2ffda01b02706a89bef7491)


#### **Deploy in AWS EC2** ####
[Instructions](https://gist.github.com/ninp0/ba9698b7ca5a7696abf37a579097a2f2)


#### **Deploy in Docker Container** ####
[Deploy PWN Fuzz Network Application Protocol](https://gist.github.com/ninp0/b2e9831429b2223bbbe913294e7a1690)

[Deploy PWN Prototyping Driver](https://gist.github.com/ninp0/450666731c4ac52c1e218d55579a0580)

[Deploy PWN Public IP Checking Driver](https://gist.github.com/ninp0/d56bd37d9c25886e6a89e38ec635ec0f)

[Deploy PWN SAST)](https://gist.github.com/ninp0/2478ff7bbce0036a11f729d715923f28)

[Deploy PWN Transparent Browser](https://gist.github.com/ninp0/b96aec0c64c2c8e6ffee342bafe4b17a)

#### **Deploy in VirtualBox** ####
[Instructions](https://gist.github.com/ninp0/f01c4f129a34684f30f5cd2935c0f0d8)
  

#### **Deploy in VMware** ####
[Instructions](https://gist.github.com/ninp0/2e97f1f34c956e90294f214e1edd2ffb)


#### **Deploy in vSphere** ####
[Instructions](https://gist.github.com/ninp0/f1baf4fcd4ae9d23ae35ed7a7d083ae9)



### **General Usage** ###
[General Usage Quick-Start](https://github.com/0dayinc/pwn/wiki/General-PWN-Usage)

It's wise to rebuild pwn often as this repo has numerous releases/week (unless you're in the Kali box, then it's handled for you daily in the Jenkins job called, "selfupdate-pwn":
  ```
  $ cd /opt/pwn && ./update_pwn.sh && pwn
  pwn[v0.4.334]:001 >>> PWN.help
  ```


### **Driver Documentation** ###
[For a list of existing drivers and their usage](https://github.com/0dayinc/pwn/wiki/PWN-Driver-Documentation)



I hope you enjoy PWN and remember...ensure you always have permission prior to carrying out any sort of hacktivities.  Now - go hackomate all the things!

### **Merchandise** ###

[![Coffee Mug](https://image.spreadshirtmedia.com/image-server/v1/products/T949A2PA1998PT25X7Y0D1020472684FS8982/views/3,width=650,height=650,appearanceId=2,backgroundColor=f6f6f6,crop=detail,modelId=1333,version=1546851285/https0dayinccom.jpg)](https://shop.spreadshirt.com/0day/redfingerprint-A5c3e49cd1cbf3a0b9596ae58?productType=949&appearance=2&size=29)

[![Womens Off the Air Hoodie](https://image.spreadshirtmedia.com/image-server/v1/products/T444A2PA801PT17X165Y17D1020472921FS3041/views/1,width=650,height=650,appearanceId=2,backgroundColor=f6f6f6/off-the-air.jpg)](https://shop.spreadshirt.com/0day/offtheair-A5c3e4bfc1cbf3a0b9597aca9?productType=444&appearance=2)

[![Red Fingerprint](https://image.spreadshirtmedia.com/image-server/v1/products/T803A2PA1648PT26X47Y0D1020472684FS6537/views/1,width=650,height=650,appearanceId=2/https0dayinccom.jpg)](https://shop.spreadshirt.com/0day/redfingerprint-A5c3e49cd1cbf3a0b9596ae58?productType=803&appearance=2&size=29)

[![0day Inc.](https://image.spreadshirtmedia.com/image-server/v1/products/T951A70PA3076PT17X0Y73D1020472680FS8515/views/1,width=650,height=650,appearanceId=70/https0dayinccom.jpg)](https://shop.spreadshirt.com/0day/0dayinc-A5c3e498cf937643162a01b5f?productType=951&appearance=70)

[![Mens Black Fingerprint Hoodie](https://image.spreadshirtmedia.com/image-server/v1/products/T111A2PA3208PT17X169Y51D1020472728FS6268/views/1,width=650,height=650,appearanceId=2/https0dayinccom.jpg)](https://shop.spreadshirt.com/0day/blackfingerprint-A5c3e49db1cbf3a0b9596b4d0?productType=111&appearance=2)
