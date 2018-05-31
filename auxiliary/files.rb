##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

# require 'msf/core'

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpServer::HTML

  def initialize(info = {})
    super(update_info(info,
                      'Name'           => 'HttpServer mixin example',
                      'Description'    => "
                        Here's an example of using the HttpServer mixin
                      ",
                      'License'        => MSF_LICENSE,
                      'Author'         => ['sinn3r'],
                      'References'     =>
                        [
                          ['URL', 'http://metasploit.com']
                        ],
                      'Platform'       => 'win',
                      'Targets'        =>
                        [
                          ['Generic', {}]
                        ],
                      'DisclosureDate' => 'Apr 1 2013',
                      'DefaultTarget'  => 0))
    register_options([
                       OptString.new('PATH', [true,
                                              'Path on host of files'])
                     ])
  end

  DEFAULT_CONTENT_TYPE = 'application/octet-stream'
  CONTENT_TYPE_MAPPING = {
    'html' => 'text/html',
    'txt' => 'text/plain',
    'png' => 'image/png',
    'jpg' => 'image/jpeg'
  }

  def content_type(path)
    ext = File.extname(path).split('.').last
    CONTENT_TYPE_MAPPING.fetch(ext, DEFAULT_CONTENT_TYPE)
  end

  def run
    exploit
  end

  def on_request_uri(cli, request)
    path = CGI.unescape(URI(request.uri).path)
    path.slice! datastore['URIPATH']

    if request.method != "GET"
      send_not_found(cli)
      return
    end
    file = File.join(datastore['PATH'], path)
    contents = "404 not found #{file}"
    mime_type = DEFAULT_CONTENT_TYPE

    unless File.exist?(file)
      print_status("Handling 404 '#{request.uri}'")
      send_not_found(cli)
      return
    end
    if File.directory?(file)
      print_status("Handling 404 '#{request.uri}'")
      send_not_found(cli)
      return
    end
    contents = File.read(file)
    mime_type = content_type(file)
    print_status("Handling 200 #{request.method} '#{request.uri}'")
    send_response_html(cli, contents, 'Content-Type' => mime_type)
  end
end
