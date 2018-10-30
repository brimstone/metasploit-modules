##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Post
  def initialize(info = {})
    super(update_info(info,
                      'Name'          => 'Harden a system',
                      'Description'   => %q( This module hardens a windows system),
                      'License'       => MSF_LICENSE,
                      'Author'        => [ 'brimstone' ],
                      'Platform'      => %w(win),
                      'SessionTypes'  => [ 'meterpreter' ]
                     ))
  end

  def run
    # Sort our our OS
    uid = client.sys.config.getuid
    # Make sure we're SYSTEM
    if uid !~ /SYSTEM,/
      print_error("I am not SYSTEM. Must be SYSTEM to harden.")
      return
    end
    print_status("I'm doing things!")
  end
end
