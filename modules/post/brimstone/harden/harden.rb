##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Post
  def initialize(info = {})
    super(update_info(info,
                      'Name'          => 'Harden a system',
                      'Description'   => %q( This module hardens a system),
                      'License'       => MSF_LICENSE,
                      'Author'        => [ 'brimstone' ],
                      'Platform'      => %w(linux unix win),
                      'SessionTypes'  => [ 'meterpreter' ]
                     ))
    # register_options(
    # [
    #     OptString.new( 'COMMAND', [false, 'The entire command line to execute on the session'])
    # ])
  end

  def run
    # Sort our our OS
    os = sysinfo['OS']
    if os =~ /Linux/
      m = framework.post.create("brimstone/harden_linux")
    elsif os =~ /Windows/
      m = framework.post.create("brimstone/harden_windows")
    else
      print_error("Unsupported OS: #{os}")
      return
    end

    if m.nil?
      print_error("Error initializing OS specific hardening module")
      return
    end

    print_status("Starting OS specific module")
    m.datastore['SESSION'] = datastore['SESSION']
    m.run_simple(
      'LocalInput'  => user_input,
      'LocalOutput' => user_output
    )
  end
end
