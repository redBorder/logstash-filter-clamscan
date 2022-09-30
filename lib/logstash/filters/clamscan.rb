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

    clamscan_info = `#{@clamscan_bin} -d #{@database_dir} #{@file_path}`

    fields = clamscan_info.split(/\n+/)

    fields = fields.map{ |f| f.split(/: /)  }

    score = fields[6][1] == "1" ? 100 : 0

    clamscan_json = {
      #Virus Family
      "Virus Family" => score == 0 ? "Unknown" : fields[0][1].split(/ /, 2).first, #Get only family name. Example raw family: "Win.Trojan.Hzzv-7433640-0 FOUND"
      #Known viruses
      fields[2][0] => fields[2][1],
      #Engine version
      fields[3][0] => fields[3][1],
      #Data scanned
      fields[7][0] => fields[7][1],
    }

  [clamscan_json, score]
  end

  public
  def filter(event)

    @file_path = event.get(@file_field)
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
