# encoding: utf-8
require "logstash/filters/base"
require "logstash/namespace"

require 'json'

class LogStash::Filters::Clamscan < LogStash::Filters::Base

  config_name "clamscan"

  # Clamscan binary path
  config :clamscan_bin,      :validate => :string,  :default => "/usr/bin/clamscan"
  # File that is going to be analyzed
  config :file_field,        :validate => :string,  :default => "[path]"
  # Loader weight
  config :weight, :default => 1.0
  # Where you want the data to be placed
  config :target, :validate => :string, :default => "clamscan"
  # Where you want the score to be placed
  config :score_name, :validate => :string, :default => "fb_clamscan"
  # Where you want the latency to be placed
  config :latency_name, :validate => :string, :default => "clamscan_latency"


  public
  def register
    # Add instance variables
  end # def register

  private

  def get_clamscan_info

    unless File.exist?(@clamscan_bin)
      return [{"Error" => "Clamscan binary is not in #{@clamscan_bin}."},0]
    end

    unless File.exist?(@file_path)
      return [{"Error" => "File #{@file_path} does not exist."},0]
    end

    clamscan_info = `#{@clamscan_bin} #{@file_path}`

    fields = clamscan_info.split(/\n+/)

    fields = fields.map{ |f| f.split(/: /)  }

    score = fields[6][1] == "1" ? 100 * @weight : 0

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

    starting_time = Process.clock_gettime(Process::CLOCK_MONOTONIC)
    clamscan_result,score = get_clamscan_info

    ending_time  = Process.clock_gettime(Process::CLOCK_MONOTONIC)
    elapsed_time = (ending_time - starting_time).round(1)

    event.set(@latency_name, elapsed_time)
    event.set(@target, clamscan_result)
    event.set(@score_name, score)
    # filter_matched should go in the last line of our successful code
    filter_matched(event)

  end  # def filter(event)
end # class LogStash::Filters::Clamscan
