![PWN](https://raw.githubusercontent.com/0dayInc/pwn/master/documentation/PWN.png)

### **Table of Contents** ###
- [Intro](#intro)
  * [What is PWN](#what-is-pwn)
  * [Why PWN](#why-pwn)
  * [How PWN Works](#how-pwn-works)
- [Installation](#installation)
- [General Usage](#general-usage)
- [Call to Arms](#call-to-arms)
- [Module Documentation](#module-documentation)
- [Keep Us Caffeinated](#keep-us-caffeinated)
- [0x004D65726368](#0x004D65726368)


### **Intro** ###
#### **What is PWN** ####
PWN (Pronounced /pōn/ or pone), is an open security automation framework that aims to stand on the shoulders of security giants, promoting trust and innovation.  Build your own custom automation drivers freely and easily using pre-built modules.


#### **Why PWN** ####
It's easy to agree that while corporate automation is a collection of proprietary source code, the core modules used to produce automated solutions should be open for all eyes to continuously promote trust and innovation...broad collaboration is key to any automation framework's success, particularly in the cyber security arena.


#### **How PWN Works** ####
Leveraging various pre-built modules and the pwn prototyper, you can mix-and-match modules to test, record, replay, and rollout your own custom security automation packages known as, "drivers." Here are some [example drivers](https://github.com/0dayInc/pwn/tree/master/bin) distributed with PWN.



#### **Installation** ####
Tested on Debian-Based Linux Distros, & OSX leveraging Ruby via RVM.

```
$ cd /opt
$ sudo git clone https://github.com/0dayinc/pwn
$ cd /opt/pwn
$ ./install.sh
$ ./install.sh ruby-gem
$ pwn
pwn[v0.5.549]:001 >>> PWN.help
```

[![Installing the pwn Security Automation Framework](https://raw.githubusercontent.com/0dayInc/pwn/master/documentation/pwn_install.png)](https://youtu.be/G7iLUY4FzsI)

### **General Usage** ###
[General Usage Quick-Start](https://github.com/0dayinc/pwn/wiki/General-PWN-Usage)

It's wise to update pwn often as numerous versions are released/week:
```
$ rvm list gemsets
$ rvm use ruby-4.0.1@pwn
$ gem uninstall --all --executables pwn
$ gem install --verbose pwn
$ pwn
pwn[v0.5.549]:001 >>> PWN.help
```

If you're using a multi-user install of RVM do:
```
$ rvm list gemsets
$ rvm use ruby-4.0.1@pwn
$ rvmsudo gem uninstall --all --executables pwn
$ rvmsudo gem install --verbose pwn
$ pwn
pwn[v0.5.549]:001 >>> PWN.help
```

PWN periodically upgrades to the latest version of Ruby which is reflected in `/opt/pwn/.ruby-version`.  The easiest way to upgrade to the latest version of Ruby from a previous PWN installation is to run the following script:
```
$ /opt/pwn/vagrant/provisioners/pwn.sh
```
This should update Ruby, create the necessary pwn gemset within the latest Ruby version, etc.  It's important to note that if you're running an older version of ruby, you can only upgrade the `pwn` gem to the latest version supported by the earlier version of Ruby.


### **Call to Arms** ###
If you're willing to provide access to commercial security tools (e.g. Rapid7's Nexpose, Tenable Nessus, QualysGuard, HP WebInspect, IBM Appscan, etc) please [email us](mailto:support@0dayinc.com).  This will continue to promote PWNs interoperability w/ industry-recognized security tools moving forward.  Additionally if you want to contribute to this framework's success, check out our [How to Contribute](https://github.com/0dayInc/pwn/blob/master/CONTRIBUTING.md).


### **Module Documentation** ###
Additional documentation on using PWN can be found on [RubyGems.org](https://www.rubydoc.info/gems/pwn)

I hope you enjoy PWN and remember...ensure you always have permission prior to carrying out any sort of hacktivities.  Now - go pwn all the things!

### **Keep Us Caffeinated** ###
If you've found this project useful and you're interested in supporting our efforts, we invite you to take a brief moment to keep us caffeinated:

[![Coffee](https://www.buymeacoffee.com/assets/img/custom_images/orange_img.png)](https://buymeacoff.ee/0dayinc)


### [**0x004D65726368**](https://0day.myspreadshop.com/) ###

[![PWN Sticker](https://image.spreadshirtmedia.com/image-server/v1/products/T1459A839PA3861PT28D1044068794FS8193/views/1,width=300,height=300,appearanceId=839,backgroundColor=000000/ultimate-hacker-t-shirt-to-convey-to-the-public-a-hackers-favorite-past-time.jpg)](https://0day.myspreadshop.com/stickers)

[![Coffee Mug](https://image.spreadshirtmedia.com/image-server/v1/products/T1313A1PA3933PT10X2Y25D1020472680FS6327/views/3,width=300,height=300,appearanceId=1,backgroundColor=000000/https0dayinccom.jpg)](https://0day.myspreadshop.com/accessories+mugs+%26+drinkware)

[![Mouse Pad](https://image.spreadshirtmedia.com/image-server/v1/products/T993A1PA2168PT10X162Y26D1044068794S100/views/1,width=300,height=300,appearanceId=1,backgroundColor=000000/ultimate-hacker-t-shirt-to-convey-to-the-public-a-hackers-favorite-past-time.jpg)](https://0day.myspreadshop.com/accessories)

[![0day Inc.](https://image.spreadshirtmedia.com/image-server/v1/products/T951A550PA3076PT17X0Y73D1020472680FS8515/views/1,width=300,height=300,appearanceId=70,backgroundColor=000000/https0dayinccom.jpg)](https://shop.spreadshirt.com/0day/0dayinc-A5c3e498cf937643162a01b5f?productType=951&appearance=70)

[![Black Fingerprint Hoodie](https://image.spreadshirtmedia.com/image-server/v1/products/T111A2PA3208PT17X169Y51D1020472728FS6268/views/1,width=300,height=300,appearanceId=2/https0dayinccom.jpg)](https://shop.spreadshirt.com/0day/blackfingerprint-A5c3e49db1cbf3a0b9596b4d0?productType=111&appearance=2)
