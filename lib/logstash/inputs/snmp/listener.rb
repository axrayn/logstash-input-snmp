require "java"
require "logstash-input-snmp_jars.rb"

require "logstash/inputs/base"
require "logstash/namespace"
require "logstash/util/loggable"

java_import "java.net.InetAddress"
java_import "org.snmp4j.CommandResponder"
java_import "org.snmp4j.CommandResponderEvent"
java_import "org.snmp4j.CommunityTarget"
java_import "org.snmp4j.MessageDispatcher"
java_import "org.snmp4j.MessageDispatcherImpl"
java_import "org.snmp4j.MessageException"
java_import "org.snmp4j.PDU"
java_import "org.snmp4j.PDUv1"
java_import "org.snmp4j.Snmp"
java_import "org.snmp4j.mp.SnmpConstants"
java_import "org.snmp4j.mp.MPv1"
java_import "org.snmp4j.mp.MPv2c"
java_import "org.snmp4j.security.SecurityProtocols"
java_import "org.snmp4j.smi.IpAddress"
java_import "org.snmp4j.smi.TcpAddress"
java_import "org.snmp4j.smi.UdpAddress"
java_import "org.snmp4j.util.MultiThreadedMessageDispatcher"
java_import "org.snmp4j.util.ThreadPool"

module Logstash
  class SnmpListenerError < StandardError
  end
  
  class SnmpListener
    include CommandResponder
    include LogStash::Util::Loggable
    
    def initialize(protocol, address, port, community, mib, threads, strip_root = 0, path_length = 0, queue)
      @queue = queue
      ipaddr = InetAddress.getByName(address)
      transport = case protocol.to_s
        when "udp"
          uaddress = UdpAddress.new
          uaddress.setInetAddress(ipaddr)
          uaddress.setPort(port.to_i)
          DefaultUdpTransportMapping.new(uaddress)
        when "tcp"
          taddress = TcpAddress.new(ipaddr, port)
          DefaultTcpTransportMapping.new(taddress)
        else
          raise(SnmpClientError, "invalid transport protocol specified '#{protocol.to_s}', expecting 'udp' or 'tcp'")
        end

      threadpool = ThreadPool.create("DispatcherPool", threads)
      mtdispatcher = MultiThreadedMessageDispatcher.new(threadpool, MessageDispatcherImpl.new())
        
      mtdispatcher.addMessageProcessingModel(MPv1.new)
      mtdispatcher.addMessageProcessingModel(MPv2c.new)

      SecurityProtocols.getInstance.addDefaultProtocols
      
      comtarget = CommunityTarget.new
      comtarget.setCommunity(OctetString.new(community))        

      @mib = mib
      @snmp = Snmp.new(mtdispatcher, transport)
      @snmp.addCommandResponder(self)
      
      transport.listen()
      logger.info("Trap Listener listening with community '#{community}' on '#{protocol}:#{address}/#{port}'")
    end

    SENDER_REGEX = /^(?<sender_address>.+)\/(?<sender_port>\d+)$/i
    VARBIND_REGEX = /^(?<vb_oid>[0-9\.]+) = (?<vb_value>.+)$/i
    
    def processPdu(trapmsg)
      pdu = trapmsg.getPDU
      if !pdu.nil?
        pcomm = trapmsg.getSecurityName
        psender = trapmsg.getPeerAddress
        
        ptype = pdu.getType
     
        case ptype.to_i
          when PDU::V1TRAP
            processV1Trap(pdu, pcomm, psender)
          when PDU::NOTIFICATION
            processV2Trap(pdu, pcomm, psender)
          else
            logger.info("Received unsupported trap type: '#{trapmsg}'")
        end
      end
    end
    
    def processV1Trap(pdu, pcomm, psender)
      result = {}
      varbinds = []
      varbinds = pdu.getVariableBindings
      result["trap.enterprise_oid"] = pdu.getEnterprise.to_s
      result["trap.generic_type"] = pdu.getGenericTrap
      result["trap.specific_type"] = pdu.getSpecificTrap
      result["trap.sysuptime"] = pdu.getTimestamp

      varbinds.each do |varbind|
        next if varbind.nil?
        logger.info("Varbind: '#{varbind}'")
        
        vb_details = varbind.to_s.match(VARBIND_REGEX)
        logger.info("VarbindOID: '#{vb_details["vb_oid"]}'")
        logger.info("VarbindValue: '#{vb_details["vb_value"]}'")
        result["trap.varbinds.#{@mib.map_oid(vb_details["vb_oid"], 0, 0)}"] = vb_details["vb_value"]
      end
      logger.info("Result: '#{result}'")
      logger.info("Queue in Listener is '#{@queue}'")
      
      event = LogStash::Event.new(result)
      decorate(event)
      @queue << event
    end
    
    def processV2Trap(pdu, pcomm, psender)
      varbinds = pdu.getVariableBindings
      
      result = {}
      ## to be completed once I get the queue bit working
      
      logger.info("Received v2 Trap from address: '#{psender}' with varbinds: '#{varbinds}' and full: '#{pdu}")
      event = LogStash::Event.new(result)
      decorate(event)
      @queue << event
    end
    
    
    def processListenerPDUType(type)
      logger.info("Parsing PDU Type '#{type}'")
      case type.to_i
        when PDU::V1TRAP
          "V1TRAP"
        when PDU::INFORM
          "INFORM"
        when PDU::NOTIFICATION
          "NOTIFICATION"
        when PDU::REPORT
          "REPORT"
        else
          raise(SnmpClientError, "PDU Type of '#{type}' is not supported for the trap listener, expected types are 'V1TRAP', 'INFORM', 'TRAP', 'NOTIFICATION', and 'REPORT'")
      end
    end
    
    def exit
      @snmp.close
    end
    
  end
end
