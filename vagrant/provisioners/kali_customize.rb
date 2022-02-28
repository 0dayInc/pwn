#!/usr/bin/env ruby
# frozen_string_literal: true

if ENV['PWN_ROOT']
  pwn_root = ENV['PWN_ROOT']
elsif Dir.exist?('/pwn')
  pwn_root = '/pwn'
else
  pwn_root = Dir.pwd
end

# A list of these are available in /usr/share/applications/*.desktop
panel_root = '/usr/share/applications'
wallpaper = "#{pwn_root}/documentation/pwn_wallpaper.jpg"

system("sudo chmod 777 #{panel_root}")

File.open("#{panel_root}/pwn-prototyper.desktop", 'w') do |f|
  f.puts '[Desktop Entry]'
  f.puts 'Name=pwn'
  f.puts 'Encoding=UTF-8'
  f.puts 'Exec=/bin/bash --login -c pwn'
  f.puts 'Icon=gksu-root-terminal'
  f.puts 'StartupNotify=false'
  f.puts 'Terminal=true'
  f.puts 'Type=Application'
end

File.open("#{panel_root}/pwn-chromium-jenkins.desktop", 'w') do |f|
  f.puts '[Desktop Entry]'
  f.puts 'Name=Jenkins'
  f.puts 'Encoding=UTF-8'
  f.puts 'Exec=/bin/bash --login -c "/usr/bin/chromium https://jenkins.$(hostname -d)"'
  f.puts 'Icon=dconf-editor'
  f.puts 'Type=Application'
  f.puts 'Categories=Network;WebBrowser;'
  f.puts 'MimeType=text/html;text/xml;application/xhtml_xml;application/x-mimearchive;x-scheme-handler/http;x-scheme-handler/https;'
  f.puts 'StartupWMClass=chromium'
  f.puts 'StartupNotify=true'
end

File.open("#{panel_root}/pwn-chromium-openvas.desktop", 'w') do |f|
  f.puts '[Desktop Entry]'
  f.puts 'Name=OpenVAS'
  f.puts 'Encoding=UTF-8'
  f.puts 'Exec=/bin/bash --login -c "/usr/bin/chromium https://openvas.$(hostname -d)"'
  f.puts 'Terminal=false'
  f.puts 'X-MultipleArgs=false'
  f.puts 'Type=Application'
  f.puts 'Icon=kali-openvas.png'
  f.puts 'Categories=Network;WebBrowser;'
  f.puts 'MimeType=text/html;text/xml;application/xhtml_xml;application/x-mimearchive;x-scheme-handler/http;x-scheme-handler/https;'
  f.puts 'StartupWMClass=chromium'
  f.puts 'StartupNotify=true'
end

File.open("#{panel_root}/pwn-msfconsole.desktop", 'w') do |f|
  f.puts '[Desktop Entry]'
  f.puts 'Name=metasploit framework'
  f.puts 'Encoding=UTF-8'
  f.puts 'Exec=sudo /bin/bash --login -c "cd /opt/metasploit-framework-dev && ./msfconsole"'
  f.puts 'Icon=kali-metasploit-framework.png'
  f.puts 'StartupNotify=false'
  f.puts 'Terminal=true'
  f.puts 'Type=Application'
end

File.open("#{panel_root}/pwn-setoolkit.desktop", 'w') do |f|
  f.puts '[Desktop Entry]'
  f.puts 'Name=social engineering toolkit'
  f.puts 'Encoding=UTF-8'
  f.puts 'Exec=sudo /bin/bash --login -c "setoolkit"'
  f.puts 'Icon=kali-set.png'
  f.puts 'StartupNotify=false'
  f.puts 'Terminal=true'
  f.puts 'Type=Application'
  f.puts 'Categories=08-exploitation-tools;13-social-engineering-tools;'
  f.puts 'X-Kali-Package=set'
end

system("sudo chown root:root #{panel_root}/*.desktop")
system("sudo chmod 755 #{panel_root}")

panel_items = [
  'pwn-prototyper.desktop',
  'terminator.desktop',
  'kali-recon-ng.desktop',
  'pwn-chromium-jenkins.desktop',
  'pwn-chromium-openvas.desktop',
  'chromium.desktop',
  'firefox-esr.desktop',
  'kali-burpsuite.desktop',
  'kali-zaproxy.desktop',
  'pwn-msfconsole.desktop',
  'kali-searchsploit.desktop',
  'pwn-setoolkit.desktop'
]

# XFCE
# Do not show icons on Desktop
system('xfconf-query --channel xfce4-desktop --property /desktop-icons/file-icons/show-home --set false')
system('xfconf-query --channel xfce4-desktop --property /desktop-icons/file-icons/show-trash --set false')
system('xfconf-query --channel xfce4-desktop --property /desktop-icons/file-icons/show-removable --set false')
system('xfconf-query --channel xfce4-desktop --property /desktop-icons/file-icons/show-filesystem --set false')

# Create the Custom Kali Panel
system('xfce4-clipman &')
panel_items.each do |panel_item|
  system("xfce4-panel --add=launcher #{panel_root}/#{panel_item}")
end

# Use the PWN Wallpaper for LightDm Greeter
# Keep space between c\ background...
system("sudo sed -i '/background/c\ background = #{wallpaper}' /etc/lightdm/lightdm-gtk-greeter.conf")
# Use the PWN Wallpaper
system(
  "
    xfconf-query \
      --channel xfce4-desktop \
      --list | \
        grep image | \
        grep -e path -e last | \
        while read property; do \
          xfconf-query \
            --channel xfce4-desktop \
            --property $property \
            --set #{wallpaper}; \
        done
  "
)
