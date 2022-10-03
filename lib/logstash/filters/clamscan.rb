# encoding: utf-8
require "logstash/filters/base"
require "logstash/namespace"

require 'json'
require 'aerospike'

require_relative "util/aerospike_config"
require_relative "util/aerospike_manager"

class LogStash::Filters::Clamscan < LogStash::Filters::Base

  include Aerospike

  config_name "clamscan"

  # Clamscan binary path
  config :clamscan_bin,                     :validate => :string,           :default => "/usr/bin/clamscan"
  # Clamscan database path
  config :database_dir,                     :validate => :string,           :default => "/var/lib/clamav"
  # File that is going to be analyzed
  config :file_field,                       :validate => :string,           :default => "[path]"
  # Where you want the data to be placed
  config :target,                           :validate => :string,           :default => "clamscan"
  # Where you want the score to be placed
  config :score_name,                       :validate => :string,           :default => "fb_clamscan"
  # Where you want the latency to be placed
  config :latency_name,                     :validate => :string,           :default => "clamscan_latency"
  #Aerospike server in the form "host:port"
  config :aerospike_server,                 :validate => :string,           :default => ""
  #Namespace is a Database name in Aerospike
  config :aerospike_namespace,              :validate => :string,           :default => "malware"
  #Set in Aerospike is similar to table in a relational database.
  # Where are scores stored
  config :aerospike_set,                    :validate => :string,           :default => "hashScores"


  public
  def register
    # Add instance variables
    begin
      @aerospike_server = AerospikeConfig::servers if @aerospike_server.empty?
      @aerospike_server = @aerospike_server[0] if @aerospike_server.class.to_s == "Array"
      host,port = @aerospike_server.split(":")
      @aerospike = Client.new(Host.new(host, port))

    rescue Aerospike::Exceptions::Aerospike => ex
      @logger.error(ex.message)
    end
  end # def register

  private

  def get_clamscan_info
    clamscan_info = {}
    score = -1

    unless File.exist?(@clamscan_bin)
      @logger.error("Clamscan binary is not in #{@clamscan_bin}.")
      return [clamscan_info,score]
    end

    unless File.exist?(@file_path)
      @logger.error("File #{@file_path} does not exist.")
      return [clamscan_info,score]
    end

    command = "nice -n 19 ionice -c2 -n7 #{@clamscan_bin} -i --stdout -d #{@database_dir} #{@file_path}"
    result = `#{command}`

    clamscan_info = {}
    result.split(/\n+/).each{|e| e.include?":" and clamscan_info[e.split(":").first.strip] = e.split(":").last.strip }
    score = clamscan_info["Infected files"].to_i != 0 ? 100 : 0  rescue score = 0
    virus_family = score == 0 ? "Unknown" : clamscan_info[@file_path].split.first rescue virus_family = "Unknown"

    clamscan_json = {
      "Virus Family" => virus_family, 
      "Know viruses" => clamscan_info["Known viruses"],
      "Engine version" => clamscan_info["Engine version"],
      "Data scanned" => clamscan_info["Data scanned"]
    }

  [clamscan_json, score]
  end

  public
  def filter(event)

    @file_path = event.get(@file_field)
    puts "[clamscan] processing #{@file_path}"

    begin
      @hash = Digest::SHA2.new(256).hexdigest File.read @file_path
    rescue Errno::ENOENT => ex
      @logger.error(ex.message)
    end

    starting_time = Process.clock_gettime(Process::CLOCK_MONOTONIC)
    clamscan_result,score = get_clamscan_info

    ending_time  = Process.clock_gettime(Process::CLOCK_MONOTONIC)
    elapsed_time = (ending_time - starting_time).round(1)

    event.set(@latency_name, elapsed_time)
    event.set(@target, clamscan_result)
    event.set(@score_name, score)

    AerospikeManager::update_malware_hash_score(@aerospike, @aerospike_namespace, @aerospike_set, @hash, @score_name, score, "fb")

    # filter_matched should go in the last line of our successful code
    filter_matched(event)

  end  # def filter(event)
end # class LogStash::Filters::Clamscan
