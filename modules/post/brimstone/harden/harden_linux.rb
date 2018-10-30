##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Post
  def initialize(info = {})
    super(update_info(info,
                      'Name'          => 'Harden a linux system',
                      'Description'   => %q( This module hardens linux systems),
                      'License'       => MSF_LICENSE,
                      'Author'        => [ 'brimstone' ],
                      'Platform'      => %w(linux),
                      'SessionTypes'  => [ 'meterpreter' ]
                     ))
  end

  def run
    # Sort our our OS
    uid = client.sys.config.getuid
    # Make sure we're root
    print_status("UID: #{uid}")
    if uid !~ /uid=0,/
      print_error("I am not root. Must be root to harden.")
      return
    end

    # TODO: Lock down firewall
    # TODO: Setup persistent connection
    print_status("I'm doing things!")
  end
end
