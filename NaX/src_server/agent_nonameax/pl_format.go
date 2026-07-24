package main

import (
	"encoding/binary"
	"fmt"
	"sort"
	"strings"
	"time"

	adaptix "github.com/Adaptix-Framework/axc2"
)

// win32ErrorName returns the symbolic name of a common Win32 error code.
func win32ErrorName(code uint32) string {
	switch code {
	case 1:
		return "ERROR_INVALID_FUNCTION"
	case 2:
		return "ERROR_FILE_NOT_FOUND"
	case 3:
		return "ERROR_PATH_NOT_FOUND"
	case 4:
		return "ERROR_TOO_MANY_OPEN_FILES"
	case 5:
		return "ERROR_ACCESS_DENIED"
	case 6:
		return "ERROR_INVALID_HANDLE"
	case 15:
		return "ERROR_INVALID_DRIVE"
	case 17:
		return "ERROR_NOT_SAME_DEVICE"
	case 18:
		return "ERROR_NO_MORE_FILES"
	case 19:
		return "ERROR_WRITE_PROTECT"
	case 32:
		return "ERROR_SHARING_VIOLATION"
	case 33:
		return "ERROR_LOCK_VIOLATION"
	case 80:
		return "ERROR_FILE_EXISTS"
	case 87:
		return "ERROR_INVALID_PARAMETER"
	case 112:
		return "ERROR_DISK_FULL"
	case 123:
		return "ERROR_INVALID_NAME"
	case 145:
		return "ERROR_DIR_NOT_EMPTY"
	case 183:
		return "ERROR_ALREADY_EXISTS"
	case 206:
		return "ERROR_FILENAME_EXCED_RANGE"
	case 267:
		return "ERROR_DIRECTORY"
	default:
		return "unknown"
	}
}

/* ========= [ ps list helpers ] ========= */

func readLenPrefixedStringGo(data []byte, cursor int) (string, int) {
	if cursor+2 > len(data) {
		return "", cursor
	}
	n := int(binary.LittleEndian.Uint16(data[cursor : cursor+2]))
	cursor += 2
	if cursor+n > len(data) {
		return "", cursor
	}
	s := string(data[cursor : cursor+n])
	cursor += n
	return s, cursor
}

func decodePsListResult(agentData adaptix.AgentData, taskIdStr string, data []byte) (string, string) {
	if len(data) < 5 {
		return "ps: empty result", ""
	}
	result := data[0]
	if result == 0 {
		code := binary.LittleEndian.Uint32(data[1:5])
		return fmt.Sprintf("ps: error code %d (%s)", code, win32ErrorName(code)), ""
	}

	processCount := int(binary.LittleEndian.Uint32(data[1:5]))
	if processCount == 0 {
		return "ps: no processes found", ""
	}

	type psEntry struct {
		Pid       uint
		Ppid      uint
		SessionId uint
		Arch      string
		Elevated  bool
		Context   string
		Name      string
	}

	cursor := 5
	var proclist []psEntry
	contextMaxSize := 10

	for i := 0; i < processCount; i++ {
		if cursor+8 > len(data) {
			break
		}
		pid := uint(binary.LittleEndian.Uint16(data[cursor : cursor+2]))
		cursor += 2
		ppid := uint(binary.LittleEndian.Uint16(data[cursor : cursor+2]))
		cursor += 2
		session := uint(binary.LittleEndian.Uint16(data[cursor : cursor+2]))
		cursor += 2
		arch64 := data[cursor]
		cursor++
		elev := data[cursor]
		cursor++

		domain, newCursor := readLenPrefixedStringGo(data, cursor)
		cursor = newCursor
		username, newCursor2 := readLenPrefixedStringGo(data, cursor)
		cursor = newCursor2
		procName, newCursor3 := readLenPrefixedStringGo(data, cursor)
		cursor = newCursor3

		archStr := ""
		if arch64 == 1 {
			archStr = "x64"
		} else if arch64 == 0 {
			archStr = "x86"
		}

		ctx := ""
		if username != "" {
			ctx = username
			if domain != "" {
				ctx = domain + "\\" + username
			}
			if elev > 0 {
				ctx += " *"
			}
			if len(ctx) > contextMaxSize {
				contextMaxSize = len(ctx)
			}
		}

		proclist = append(proclist, psEntry{
			Pid: pid, Ppid: ppid, SessionId: session,
			Arch: archStr, Elevated: elev > 0, Context: ctx, Name: procName,
		})
	}

	type treeProc struct {
		Data     psEntry
		Children []*treeProc
	}

	procMap := make(map[uint]*treeProc)
	var roots []*treeProc

	for _, proc := range proclist {
		node := &treeProc{Data: proc}
		procMap[proc.Pid] = node
	}

	for _, node := range procMap {
		if node.Data.Ppid == 0 || node.Data.Pid == node.Data.Ppid {
			roots = append(roots, node)
		} else if parent, ok := procMap[node.Data.Ppid]; ok {
			parent.Children = append(parent.Children, node)
		} else {
			roots = append(roots, node)
		}
	}

	sort.Slice(roots, func(i, j int) bool { return roots[i].Data.Pid < roots[j].Data.Pid })
	var sortChildren func(node *treeProc)
	sortChildren = func(node *treeProc) {
		sort.Slice(node.Children, func(i, j int) bool { return node.Children[i].Data.Pid < node.Children[j].Data.Pid })
		for _, child := range node.Children {
			sortChildren(child)
		}
	}
	for _, root := range roots {
		sortChildren(root)
	}

	format := fmt.Sprintf(" %%-5v   %%-5v   %%-7v   %%-5v   %%-%vv   %%v", contextMaxSize)
	outputText := fmt.Sprintf(format, "PID", "PPID", "Session", "Arch", "Context", "Process")
	outputText += fmt.Sprintf("\n"+format, "---", "----", "-------", "----", "-------", "-------")

	var lines []string
	var formatTree func(node *treeProc, prefix string, isLast bool)
	formatTree = func(node *treeProc, prefix string, isLast bool) {
		branch := "├─ "
		if isLast {
			branch = "└─ "
		}
		treePrefix := prefix + branch
		d := node.Data
		line := fmt.Sprintf(format, d.Pid, d.Ppid, d.SessionId, d.Arch, d.Context, treePrefix+d.Name)
		lines = append(lines, line)

		childPrefix := prefix
		if isLast {
			childPrefix += "    "
		} else {
			childPrefix += "│   "
		}
		for i, child := range node.Children {
			formatTree(child, childPrefix, i == len(node.Children)-1)
		}
	}

	for i, root := range roots {
		formatTree(root, "", i == len(roots)-1)
	}

	outputText += "\n" + strings.Join(lines, "\n")

	var guiProcList []adaptix.ListingProcessDataWin
	for _, p := range proclist {
		guiProcList = append(guiProcList, adaptix.ListingProcessDataWin{
			Pid: p.Pid, Ppid: p.Ppid, SessionId: p.SessionId,
			Arch: p.Arch, Context: p.Context, ProcessName: p.Name,
		})
	}
	if Ts != nil {
		task := adaptix.TaskData{AgentId: agentData.Id, TaskId: taskIdStr}
		Ts.TsClientGuiProcessWindows(task, guiProcList)
	}

	return fmt.Sprintf("Process list (%d entries)", len(proclist)), outputText
}

// naxOsVersion maps PEB major/minor/build to a human-readable OS string.
func naxOsVersion(major, minor uint32, build uint16, arch string) string {
	ver := "unknown"
	b := uint32(build)
	switch {
	case major == 10 && minor == 0 && b >= 22000:
		ver = "Win 11"
	case major == 10 && minor == 0 && b >= 19045:
		ver = "Win 10"
	case major == 10 && minor == 0:
		ver = "Win 10"
	case major == 6 && minor == 3:
		ver = "Win 8.1"
	case major == 6 && minor == 2:
		ver = "Win 8"
	case major == 6 && minor == 1:
		ver = "Win 7"
	}
	return fmt.Sprintf("%s %s (Build %d)", ver, arch, build)
}

/* ========= [ ls helpers ] ========= */

func decodeLsResult(data []byte) (string, string) {
	if len(data) < 4 {
		return "ls: empty result", ""
	}
	pathLen := int(binary.LittleEndian.Uint16(data[0:2]))
	if 2+pathLen+2 > len(data) {
		return "ls: malformed result", ""
	}
	path := string(data[2 : 2+pathLen])
	count := int(binary.LittleEndian.Uint16(data[2+pathLen : 4+pathLen]))
	pos := 4 + pathLen

	type lsEntry struct {
		isDir bool
		attrs byte
		size  uint32
		mtime uint32
		name  string
	}

	var dirs, files []lsEntry
	for i := 0; i < count; i++ {
		if pos+11 > len(data) {
			break
		}
		e := lsEntry{
			isDir: data[pos] != 0,
			attrs: data[pos+1],
			size:  binary.LittleEndian.Uint32(data[pos+2 : pos+6]),
			mtime: binary.LittleEndian.Uint32(data[pos+6 : pos+10]),
		}
		nlen := int(data[pos+10])
		if pos+11+nlen > len(data) {
			break
		}
		e.name = string(data[pos+11 : pos+11+nlen])
		pos += 11 + nlen
		if e.isDir {
			dirs = append(dirs, e)
		} else {
			files = append(files, e)
		}
	}

	all := append(dirs, files...)

	header := fmt.Sprintf(" %-8s %-5s %-14s %-20s  %s\n",
		"Type", "Attr", "Size", "Last Modified", "Name")
	header += fmt.Sprintf(" %-8s %-5s %-14s %-20s  %s",
		"----", "----", "---------", "----------------", "----")

	body := ""
	for _, e := range all {
		t := time.Unix(int64(e.mtime), 0).UTC()
		ts := fmt.Sprintf("%02d/%02d/%d %02d:%02d", t.Day(), t.Month(), t.Year(), t.Hour(), t.Minute())
		typeStr := ""
		if e.isDir {
			typeStr = "dir"
		}
		attrStr := lsAttrString(e.attrs, e.isDir)
		sizeStr := ""
		if !e.isDir {
			sizeStr = sizeBytesToFormat(int64(e.size))
		}
		body += fmt.Sprintf("\n %-8s %-5s %-14s %-20s  %s", typeStr, attrStr, sizeStr, ts, e.name)
	}

	msg := fmt.Sprintf("Listing '%s' (%d entries)", path, len(all))
	return msg, header + body
}

func lsAttrString(attrs byte, isDir bool) string {
	d := '-'
	if isDir {
		d = 'd'
	}
	h := '-'
	if attrs&0x02 != 0 {
		h = 'h'
	}
	s := '-'
	if attrs&0x04 != 0 {
		s = 's'
	}
	r := '-'
	if attrs&0x01 != 0 {
		r = 'r'
	}
	return fmt.Sprintf("%c%c%c%c", d, h, s, r)
}

/* ========= [ BOF helpers ] ========= */

func packBofArgs(spec string) ([]byte, error) {
	if spec == "" {
		return nil, nil
	}
	packer := NewBofPacker()
	for _, part := range splitArgs(spec) {
		idx := 0
		for idx < len(part) && part[idx] != ':' {
			idx++
		}
		var typ, val string
		if idx >= len(part) {
			typ = "str"
			val = part
		} else {
			typ = part[:idx]
			val = part[idx+1:]
		}
		switch typ {
		case "str":
			packer.AddStr(val)
		case "wstr":
			packer.AddWStr(val)
		case "int":
			var n int64
			if _, err := fmt.Sscan(val, &n); err != nil {
				return nil, fmt.Errorf("int arg %q: %w", val, err)
			}
			packer.AddInt(int32(n))
		case "short":
			var n int64
			if _, err := fmt.Sscan(val, &n); err != nil {
				return nil, fmt.Errorf("short arg %q: %w", val, err)
			}
			packer.AddShort(int16(n))
		default:
			return nil, fmt.Errorf("unknown arg type %q", typ)
		}
	}
	return packer.Bytes(), nil
}

func splitArgs(s string) []string {
	var out []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == ',' {
			out = append(out, s[start:i])
			start = i + 1
		}
	}
	out = append(out, s[start:])
	return out
}

/* ========= [ token result decoder ] ========= */

func decodeTokenGetUidResult(data []byte) (string, string) {
	if len(data) < 5 {
		return "token getuid: truncated result", ""
	}
	user, cursor := readLenPrefixedStringGo(data, 0)
	domain, cursor := readLenPrefixedStringGo(data, cursor)
	elevated := byte(0)
	if cursor < len(data) {
		elevated = data[cursor]
	}
	star := ""
	if elevated != 0 {
		star = " *"
	}
	displayText := fmt.Sprintf("%s\\%s%s", domain, user, star)
	return displayText, displayText
}

func decodeTokenStealResult(data []byte) (string, string) {
	if len(data) < 4 {
		return "token steal: truncated result", ""
	}
	tokenId := binary.LittleEndian.Uint32(data[0:4])
	user, cursor := readLenPrefixedStringGo(data, 4)
	domain, _ := readLenPrefixedStringGo(data, cursor)
	displayText := fmt.Sprintf("Stolen token %d: %s\\%s", tokenId, domain, user)
	return displayText, displayText
}

func decodeTokenMakeResult(data []byte) (string, string) {
	if len(data) < 4 {
		return "token make: truncated result", ""
	}
	tokenId := binary.LittleEndian.Uint32(data[0:4])
	user, cursor := readLenPrefixedStringGo(data, 4)
	domain, _ := readLenPrefixedStringGo(data, cursor)
	displayText := fmt.Sprintf("Created token %d: %s\\%s", tokenId, domain, user)
	return displayText, displayText
}

func decodeTokenListResult(data []byte) (string, string) {
	if len(data) < 4 {
		return "No tokens stored", ""
	}
	count := binary.LittleEndian.Uint32(data[0:4])
	if count == 0 {
		return "No tokens stored", ""
	}
	var lines []string
	lines = append(lines, fmt.Sprintf("Stored tokens: %d", count))
	lines = append(lines, fmt.Sprintf(" %-8s  %-8s  %-20s  %s", "Token", "PID", "Domain", "User"))
	lines = append(lines, fmt.Sprintf(" %-8s  %-8s  %-20s  %s", "-----", "---", "------", "----"))
	cursor := 4
	for i := uint32(0); i < count && cursor+8 <= len(data); i++ {
		tid := binary.LittleEndian.Uint32(data[cursor : cursor+4])
		cursor += 4
		pid := binary.LittleEndian.Uint32(data[cursor : cursor+4])
		cursor += 4
		user, c := readLenPrefixedStringGo(data, cursor)
		cursor = c
		domain, c := readLenPrefixedStringGo(data, cursor)
		cursor = c
		pidStr := fmt.Sprintf("%d", pid)
		if pid == 0 {
			pidStr = "logon"
		}
		lines = append(lines, fmt.Sprintf(" %-8d  %-8s  %-20s  %s", tid, pidStr, domain, user))
	}
	return lines[0], strings.Join(lines, "\n")
}

func decodeTokenPrivsResult(data []byte) (string, string) {
	if len(data) < 4 {
		return "token privs: truncated result", ""
	}
	count := binary.LittleEndian.Uint32(data[0:4])
	if count == 0 {
		return "No privileges found", ""
	}
	var lines []string
	lines = append(lines, fmt.Sprintf("Privileges: %d", count))
	lines = append(lines, fmt.Sprintf(" %-40s  %s", "Privilege", "Status"))
	lines = append(lines, fmt.Sprintf(" %-40s  %s", "---------", "------"))
	cursor := 4
	for i := uint32(0); i < count && cursor+2 <= len(data); i++ {
		name, c := readLenPrefixedStringGo(data, cursor)
		cursor = c
		if cursor+4 > len(data) {
			break
		}
		attrs := binary.LittleEndian.Uint32(data[cursor : cursor+4])
		cursor += 4
		status := "Disabled"
		if attrs&0x00000002 != 0 {
			status = "Enabled"
		}
		if attrs&0x00000001 != 0 {
			status = "Enabled (default)"
		}
		lines = append(lines, fmt.Sprintf(" %-40s  %s", name, status))
	}
	return lines[0], strings.Join(lines, "\n")
}

func sizeBytesToFormat(size int64) string {
	const unit = 1024
	if size < unit {
		return fmt.Sprintf("%d B", size)
	}
	div, exp := int64(unit), 0
	for n := size / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(size)/float64(div), "KMGTPE"[exp])
}
