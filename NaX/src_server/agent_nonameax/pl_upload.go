package main

import (
	"encoding/binary"
	"fmt"
	"math/rand"
	"strconv"
	"strings"

	adaptix "github.com/Adaptix-Framework/axc2"
)

type uploadSession struct {
	AgentId     string
	RemotePath  string
	FileData    []byte
	ChunkSize   int
	MemoryId    uint32
	TotalSize   int
	TotalChunks int
	ChunksSent  int
	ChunksAcked int32
}

func startUploadSession(agentId string, remotePath string, fileContent []byte, chunkSize int) {
	memoryId := rand.Uint32()
	totalChunks := (len(fileContent) + chunkSize - 1) / chunkSize
	session := &uploadSession{
		AgentId:     agentId,
		RemotePath:  remotePath,
		FileData:    fileContent,
		ChunkSize:   chunkSize,
		MemoryId:    memoryId,
		TotalSize:   len(fileContent),
		TotalChunks: totalChunks,
	}
	activeUploads.Store(memoryId, session)
	queueSaveMemoryChunk(session)
}

func queueSaveMemoryChunk(session *uploadSession) {
	if session.ChunksSent >= session.TotalChunks {
		return
	}
	start := session.ChunksSent * session.ChunkSize
	end := start + session.ChunkSize
	if end > len(session.FileData) {
		end = len(session.FileData)
	}
	chunk := session.FileData[start:end]
	chunkLen := uint32(len(chunk))

	argsLen := uint32(12) + chunkLen
	data := make([]byte, 5+argsLen)
	data[0] = CMD_SAVEMEMORY
	binary.LittleEndian.PutUint32(data[1:5], argsLen)
	off := uint32(5)
	binary.LittleEndian.PutUint32(data[off:off+4], session.MemoryId)
	off += 4
	binary.LittleEndian.PutUint32(data[off:off+4], uint32(session.TotalSize))
	off += 4
	binary.LittleEndian.PutUint32(data[off:off+4], chunkLen)
	off += 4
	copy(data[off:], chunk)

	taskId := fmt.Sprintf("%08x", rand.Uint32())
	taskMemoryIds.Store(taskId, session.MemoryId)
	session.ChunksSent++

	taskData := adaptix.TaskData{
		TaskId:  taskId,
		Type:    taskTypeTask,
		AgentId: session.AgentId,
		Data:    data,
		Sync:    false,
	}
	if Ts != nil {
		Ts.TsTaskCreate(session.AgentId, "", "", taskData)
	}
}

func queueUploadTask(session *uploadSession) {
	pathB := []byte(session.RemotePath)
	totalArgs := 4 + 4 + len(pathB)
	data := make([]byte, 1+4+totalArgs)
	data[0] = CMD_UPLOAD
	binary.LittleEndian.PutUint32(data[1:5], uint32(totalArgs))
	off := 5
	binary.LittleEndian.PutUint32(data[off:off+4], session.MemoryId)
	off += 4
	binary.LittleEndian.PutUint32(data[off:off+4], uint32(len(pathB)))
	off += 4
	copy(data[off:], pathB)

	taskId := fmt.Sprintf("%08x", rand.Uint32())
	taskMemoryIds.Store(taskId, session.MemoryId)

	taskData := adaptix.TaskData{
		TaskId:  taskId,
		Type:    taskTypeTask,
		AgentId: session.AgentId,
		Data:    data,
		Sync:    true,
	}
	if Ts != nil {
		Ts.TsTaskCreate(session.AgentId, "", "", taskData)
	}
}

func humanSize(n int) string {
	if n >= 1024*1024 && n%(1024*1024) == 0 {
		return fmt.Sprintf("%dMB", n/(1024*1024))
	}
	if n >= 1024 && n%1024 == 0 {
		return fmt.Sprintf("%dKB", n/1024)
	}
	return fmt.Sprintf("%d bytes", n)
}

func parseChunkSize(raw string) (int, error) {
	raw = strings.TrimSpace(strings.ToUpper(raw))
	multiplier := 1
	if strings.HasSuffix(raw, "MB") {
		multiplier = 1024 * 1024
		raw = strings.TrimSuffix(raw, "MB")
	} else if strings.HasSuffix(raw, "KB") {
		multiplier = 1024
		raw = strings.TrimSuffix(raw, "KB")
	} else if strings.HasSuffix(raw, "B") {
		raw = strings.TrimSuffix(raw, "B")
	}
	n, err := strconv.Atoi(strings.TrimSpace(raw))
	if err != nil {
		return 0, fmt.Errorf("invalid chunk size: %w", err)
	}
	size := n * multiplier
	if size < UPLOAD_CHUNK_MIN {
		return 0, fmt.Errorf("chunk size too small (min %d bytes)", UPLOAD_CHUNK_MIN)
	}
	if size > UPLOAD_CHUNK_MAX {
		return 0, fmt.Errorf("chunk size too large (max %d bytes / %dMB)", UPLOAD_CHUNK_MAX, UPLOAD_CHUNK_MAX/(1024*1024))
	}
	return size, nil
}
