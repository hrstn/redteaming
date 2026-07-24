package main

import (
	"encoding/binary"

	adaptix "github.com/Adaptix-Framework/axc2"
)

/* ========= [ tunnel wire constants ] ========= */

const (
	cmdTunnelConnectTCP byte = 0x3E
	cmdTunnelWriteTCP   byte = 0x40
	cmdTunnelClose      byte = 0x42
	cmdTunnelReverse    byte = 0x43
	cmdTunnelAccept     byte = 0x44
	cmdTunnelPause      byte = 0x45
	cmdTunnelResume     byte = 0x46

	STATUS_TUNNEL byte = 0x20
)

/* ========= [ task builder ] ========= */

func tunnelTask(cmdId byte, args []byte) adaptix.TaskData {
	buf := make([]byte, 5+len(args))
	buf[0] = cmdId
	binary.LittleEndian.PutUint32(buf[1:5], uint32(len(args)))
	copy(buf[5:], args)
	return adaptix.TaskData{
		Type: adaptix.TASK_TYPE_PROXY_DATA,
		Data: buf,
		Sync: false,
	}
}

/* ========= [ TunnelCallbacks ] ========= */

func tunnelConnectTCP(channelId, tunnelType, addressType int, address string, port int) adaptix.TaskData {
	addrBytes := []byte(address)
	args := make([]byte, 4+4+4+len(addrBytes)+4)
	binary.LittleEndian.PutUint32(args[0:4], uint32(channelId))
	binary.LittleEndian.PutUint32(args[4:8], uint32(tunnelType))
	binary.LittleEndian.PutUint32(args[8:12], uint32(len(addrBytes)))
	copy(args[12:12+len(addrBytes)], addrBytes)
	binary.LittleEndian.PutUint32(args[12+len(addrBytes):], uint32(port))
	return tunnelTask(cmdTunnelConnectTCP, args)
}

func tunnelConnectUDP(channelId, tunnelType, addressType int, address string, port int) adaptix.TaskData {
	return adaptix.TaskData{}
}

func tunnelWriteTCP(channelId int, data []byte) adaptix.TaskData {
	args := make([]byte, 4+4+len(data))
	binary.LittleEndian.PutUint32(args[0:4], uint32(channelId))
	binary.LittleEndian.PutUint32(args[4:8], uint32(len(data)))
	copy(args[8:], data)
	return tunnelTask(cmdTunnelWriteTCP, args)
}

func tunnelWriteUDP(channelId int, data []byte) adaptix.TaskData {
	return adaptix.TaskData{}
}

func tunnelPause(channelId int) adaptix.TaskData {
	args := make([]byte, 4)
	binary.LittleEndian.PutUint32(args[0:4], uint32(channelId))
	return tunnelTask(cmdTunnelPause, args)
}

func tunnelResume(channelId int) adaptix.TaskData {
	args := make([]byte, 4)
	binary.LittleEndian.PutUint32(args[0:4], uint32(channelId))
	return tunnelTask(cmdTunnelResume, args)
}

func tunnelClose(channelId int) adaptix.TaskData {
	args := make([]byte, 4)
	binary.LittleEndian.PutUint32(args[0:4], uint32(channelId))
	return tunnelTask(cmdTunnelClose, args)
}

func tunnelReverse(tunnelId, port int) adaptix.TaskData {
	args := make([]byte, 8)
	binary.LittleEndian.PutUint32(args[0:4], uint32(tunnelId))
	binary.LittleEndian.PutUint32(args[4:8], uint32(port))
	return tunnelTask(cmdTunnelReverse, args)
}

/* ========= [ result parser ] ========= */

func processTunnelResult(agentId string, data []byte) {
	off := 0
	for off+8 <= len(data) {
		entryLen := int(binary.LittleEndian.Uint32(data[off : off+4]))
		if entryLen < 4 || off+4+entryLen > len(data) {
			break
		}
		cmdId := binary.LittleEndian.Uint32(data[off+4 : off+8])
		payload := data[off+8 : off+4+entryLen]

		switch byte(cmdId) {

		case cmdTunnelConnectTCP:
			if len(payload) < 12 {
				break
			}
			channelId := int(binary.LittleEndian.Uint32(payload[0:4]))
			result := binary.LittleEndian.Uint32(payload[8:12])
			if Ts != nil {
				if result == 0 {
					Ts.TsTunnelConnectionResume(agentId, channelId, false)
				} else {
					Ts.TsTunnelConnectionClose(channelId, false)
				}
			}

		case cmdTunnelWriteTCP:
			if len(payload) < 8 {
				break
			}
			channelId := int(binary.LittleEndian.Uint32(payload[0:4]))
			dataLen := int(binary.LittleEndian.Uint32(payload[4:8]))
			if len(payload) < 8+dataLen {
				break
			}
			if Ts != nil {
				Ts.TsTunnelConnectionData(channelId, payload[8:8+dataLen])
			}

		case cmdTunnelClose:
			if len(payload) < 12 {
				break
			}
			channelId := int(binary.LittleEndian.Uint32(payload[0:4]))
			if Ts != nil {
				Ts.TsTunnelConnectionClose(channelId, false)
			}

		case cmdTunnelReverse:
			if len(payload) < 12 {
				break
			}
			tunnelId := int(binary.LittleEndian.Uint32(payload[0:4]))
			result := binary.LittleEndian.Uint32(payload[8:12])
			if Ts != nil {
				Ts.TsTunnelUpdateRportfwd(tunnelId, result != 0)
			}

		case cmdTunnelAccept:
			if len(payload) < 8 {
				break
			}
			tunnelId := int(binary.LittleEndian.Uint32(payload[0:4]))
			newChannelId := int(binary.LittleEndian.Uint32(payload[4:8]))
			if Ts != nil {
				Ts.TsTunnelConnectionAccept(tunnelId, newChannelId)
			}

		case cmdTunnelPause:
			if len(payload) < 4 {
				break
			}
			channelId := int(binary.LittleEndian.Uint32(payload[0:4]))
			if Ts != nil {
				Ts.TsTunnelPause(channelId)
			}

		case cmdTunnelResume:
			if len(payload) < 4 {
				break
			}
			channelId := int(binary.LittleEndian.Uint32(payload[0:4]))
			if Ts != nil {
				Ts.TsTunnelResume(channelId)
			}

		default:
			naxLogErr("tunnel: unknown cmdId 0x%02x", cmdId)
		}

		off += 4 + entryLen
	}

	if off < len(data) {
		naxLogErr("tunnel: %d trailing bytes in result", len(data)-off)
	}
}
