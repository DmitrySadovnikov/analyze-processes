require 'open3'
require 'json'
require 'net/http'
require 'uri'

# Constants
DB_FILE = 'db.json'
EXCLUDED_COMMAND = 'ruby analyze_processes.rb'
API_ENDPOINT = 'https://api.perplexity.ai/chat/completions'
API_MODEL = 'sonar'
PROCESSES_FILE = 'processes.txt'

class ProcessAnalyzer
  def initialize(api_token)
    @api_token = api_token
    @db = load_database
    @old_count = 0
    @new_count = 0
  end

  def analyze_processes(read_from_file = false)
    process_info = read_from_file ? read_processes_from_file : get_current_processes

    process_info.each do |process|
      command = process[:command].split(' --')[0]
      next if command == EXCLUDED_COMMAND

      if @db.key?(command)
        @old_count += 1
      else
        puts "Analyzing: #{command}"
        @new_count += 1
        analyze_process(process, command)
      end
    end

    print_summary
  end

  private

  def load_database
    File.exist?(DB_FILE) ? JSON.parse(File.read(DB_FILE)) : {}
  rescue JSON::ParserError
    puts "Error parsing database file, creating new one"
    {}
  end

  def update_database(key, value)
    @db[key] = value
    File.write(DB_FILE, @db.to_json)
  end

  def read_processes_from_file
    stdout = File.read(PROCESSES_FILE)
    parse_process_output(stdout)
  end

  def get_current_processes
    stdout, stderr, status = Open3.capture3('ps', 'aux')
    File.write(PROCESSES_FILE, stdout)
    parse_process_output(stdout)
  end

  def parse_process_output(stdout)
    lines = stdout.split("\n")
    lines.shift # Skip header

    lines.map do |line|
      fields = line.split(/\s+/)
      pid = fields[1]
      command = fields[10..-1].join(' ').gsub(/\/Users\/[^\/]+/, '/Users/user')

      { pid: pid, command: command }
    end
  end

  def analyze_process(process, command)
    response = make_api_request(process)

    if response && response.code == '200'
      begin
        content = JSON.parse(response.body)['choices'][0]['message']['content']
        parsed_response = JSON.parse(content.gsub('```json', '').gsub('```', ''))
        status = parsed_response['status']

        puts "Status: #{parsed_response}" unless status == 'SAFE'

        update_database(command, parsed_response)
      rescue StandardError => e
        puts "Error parsing response for #{command}: #{e.message}"
      end
    end
  end

  def make_api_request(process)
    uri = URI(API_ENDPOINT)
    headers = {
      'Content-Type' => 'application/json',
      'Authorization' => "Bearer #{@api_token}"
    }

    response_example = {
      status: "SAFE",
      desc: "The command is related to..."
    }

    payload = {
      model: API_MODEL,
      messages: [
        {
          role: 'system',
          content: "You are a Mac process analysis assistant. Return a short description of the process. Return SAFE/DANGER/WARN/UNKNOWN etc in the beginning if the process is dangerous or something is wrong. Return in JSON format like: #{response_example.to_json}"
        },
        {
          role: 'user',
          content: process[:command]
        }
      ]
    }

    http = Net::HTTP.new(uri.host, uri.port)
    http.use_ssl = true
    http.post(uri.path, payload.to_json, headers)
  rescue StandardError => e
    puts "Error making request for PID #{process[:pid]}: #{e.message}"
    nil
  end

  def print_summary
    puts "Previously analyzed processes: #{@old_count}"
    puts "Newly analyzed processes: #{@new_count}"
    puts "Total processes analyzed: #{@old_count + @new_count}"
  end
end

# Main execution
if __FILE__ == $0
  if ARGV.empty?
    puts "Usage: ruby analyze_processes.rb YOUR_PERPLEXITY_API_KEY [--file]"
    exit 1
  end

  api_token = ARGV[0]
  read_from_file = ARGV.include?('--file')

  analyzer = ProcessAnalyzer.new(api_token)
  analyzer.analyze_processes(read_from_file)
end
