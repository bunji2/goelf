package main

import (
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"strings"
)

func main() {
	os.Exit(run())
}

func run() (r int) {
	var f *os.File
	f, err := os.Open(os.Args[1])
	if err != nil {
		fmt.Println(err)
		r = 1
		return
	}
	defer func(){
		e := f.Close()
		if e != nil {
			r = 6
		}
	}()

	var ident ElfIdent

	ident, err = ReadElfIdent(f)
	if err != nil {
		fmt.Println(err)
		r = 2
		return
	}
	ident.Print()
	switch ident.Class {
	case 0x00:
		r = 3
		return
	case 0x01:
		header, err := ReadElf32Header(f)
		if err != nil {
			fmt.Println(err)
			r = 4
			return
		}
		header.Print()
	case 0x02:
		header, err := ReadElf64Header(f)
		if err != nil {
			fmt.Println(err)
			r = 5
			return
		}
		header.Print()
	}

	return
}

var eiClass = []string{
	"ELFCLASSNONE", "ELFCLASS32", "ELFCLASS64",
}

var eiData = []string{
	"ELFDATANONE", "ELFDATA2LSB", "ELFDATA2MSB",
}

var eType = []string{
	"ET_NONE", "ET_REL", "ET_EXEC", "ET_DYN", "ET_CORE", "ET_LOPROC", "ET_HIPROC",
}

var eMachine = []string{
	"EM_NONE", "EM_386", "EM_ARM", "EM_X86_64", "EM_AARCH64",
}

var eVersion = []string{
	"EV_NONE", "EV_CURRENT",
}

// ElfIdent はELF識別子の型
type ElfIdent struct {
	Magic   [4]byte
	Class   byte
	Data    byte
	Version byte
	Pad     [9]byte
}

// ReadElfIdent は ELF 識別子を読みだす関数
func ReadElfIdent(r io.Reader) (ident ElfIdent, err error) {
	err = binary.Read(r, binary.LittleEndian, &ident)
	return
}

// Print は ELF 識別子を表示する関数
func (e ElfIdent) Print() {
	fmt.Printf("MAGIC:   0x%s\n", dumpBytes(e.Magic[0:4], ""))
	fmt.Printf("CLASS:   %s(0x%02X)\n", eiClass[int(e.Class)], int(e.Class))
	fmt.Printf("DATA:    %s(0x%02X)\n", eiData[int(e.Data)], int(e.Data))
	fmt.Printf("VERSION: 0x%02X\n", e.Version)
}

// Elf32Header は 32bit 版の ELF ヘッダの型
type Elf32Header struct {
	Type      uint16
	Machine   uint16
	Version   uint32
	Entry     uint32
	Phoff     uint32
	Shoff     uint32
	Flags     uint32
	Ehsize    uint16
	Phentsize uint16
	Phnum     uint16
	Shentsize uint16
	Shnum     uint16
	Shstrndx  uint16
}

// ReadElf32Header は ELF ヘッダを読みだす関数
func ReadElf32Header(r io.Reader) (h Elf32Header, err error) {
	err = binary.Read(r, binary.LittleEndian, &h)
	return
}

// Print は ELF 識別子を表示する関数
func (h Elf32Header) Print() {
	fmt.Printf("Type:      ")
	PrintType(h.Type)

	fmt.Printf("Machine:   ")
	PrintMachine(h.Machine)

	fmt.Printf("Version:   ")
	PrintVersion(h.Version)

	fmt.Printf("Entry:     0x%08X\n", h.Entry)
	fmt.Printf("Phoff:     0x%08X\n", h.Phoff)
	fmt.Printf("Shoff:     0x%08X\n", h.Shoff)
	fmt.Printf("Flags:     0x%08X\n", h.Flags)
	fmt.Printf("Ehsize:    0x%04X\n", h.Ehsize)
	fmt.Printf("Phentsize: 0x%04X\n", h.Phentsize)
	fmt.Printf("Phnum:     0x%04X\n", h.Phnum)
	fmt.Printf("Shentsize: 0x%04X\n", h.Shentsize)
	fmt.Printf("Shnum:     0x%04X\n", h.Shnum)
	fmt.Printf("Shstrndx:  0x%04X\n", h.Shstrndx)
}

// Elf64Header は 64bit 版の ELF ヘッダの型
type Elf64Header struct {
	Type      uint16
	Machine   uint16
	Version   uint32
	Entry     uint64
	Phoff     uint64
	Shoff     uint64
	Flags     uint32
	Ehsize    uint16
	Phentsize uint16
	Phnum     uint16
	Shentsize uint16
	Shnum     uint16
	Shstrndx  uint16
}

// ReadElf64Header は ELF ヘッダを読みだす関数
func ReadElf64Header(r io.Reader) (h Elf64Header, err error) {
	err = binary.Read(r, binary.LittleEndian, &h)
	return
}

// Print は ELF 識別子を表示する関数
func (h Elf64Header) Print() {
	fmt.Printf("Type:      ")
	PrintType(h.Type)

	fmt.Printf("Machine:   ")
	PrintMachine(h.Machine)

	fmt.Printf("Version:   ")
	PrintVersion(h.Version)

	fmt.Printf("Entry:     0x%016X\n", h.Entry)
	fmt.Printf("Phoff:     0x%016X\n", h.Phoff)
	fmt.Printf("Shoff:     0x%016X\n", h.Shoff)
	fmt.Printf("Flags:     0x%08X\n", h.Flags)
	fmt.Printf("Ehsize:    0x%04X\n", h.Ehsize)
	fmt.Printf("Phentsize: 0x%04X\n", h.Phentsize)
	fmt.Printf("Phnum:     0x%04X\n", h.Phnum)
	fmt.Printf("Shentsize: 0x%04X\n", h.Shentsize)
	fmt.Printf("Shnum:     0x%04X\n", h.Shnum)
	fmt.Printf("Shstrndx:  0x%04X\n", h.Shstrndx)
}

// PrintType はELF ファイルタイプを表示する関数
func PrintType(htype uint16) {
	switch htype {
	case 0, 1, 2, 3, 4:
		fmt.Printf("%s(0x%04X)\n", eType[htype], htype)
	case 0xFF00:
		fmt.Printf("%s(0x%04X)\n", eType[5], htype)
	case 0xFFFF:
		fmt.Printf("%s(0x%04X)\n", eType[6], htype)
	}
}

// PrintMachine は ELF 機種表示する関数
func PrintMachine(machine uint16) {
	switch machine {
	case 0:
		fmt.Printf("%s(0x%04X)\n", eMachine[0], machine)
	case 3:
		fmt.Printf("%s(0x%04X)\n", eMachine[1], machine)
	case 40:
		fmt.Printf("%s(0x%04X)\n", eMachine[2], machine)
	case 62:
		fmt.Printf("%s(0x%04X)\n", eMachine[3], machine)
	case 183:
		fmt.Printf("%s(0x%04X)\n", eMachine[4], machine)
	default:
		fmt.Printf("%s(0x%04X)\n", "Unknown", machine)
	}
}

// PrintVersion は ELF バージョンを表示する関数
func PrintVersion(version uint32) {
	switch version {
	case 0:
		fmt.Printf("%s(0x%08X)\n", eVersion[version], version)
	default:
		if version >= 1 {
			fmt.Printf("%s(0x%08X)\n", eVersion[1], version)
		}
	}
}

func dumpBytes(buffer []byte, sep string) string {
	tmp := make([]string, len(buffer))
	for i, b := range buffer {
		tmp[i] = fmt.Sprintf("%02X", b)
	}
	return strings.Join(tmp, sep)
}

/*
func xrun() int {
	buffer, err := readFile(os.Args[1], 16)
	if err != nil {
		return 1
	}
	//dumpBytes(buffer)
	dumpElfIdent(buffer)
	return 0
}

func readFile(filePath string, readSize int) (buffer []byte, err error) {

	var f *os.File
	f, err = os.Open(filePath)
	if err != nil {
		return
	}
	defer f.Close()
	buffer = make([]byte, readSize)
	var n int
	n, err = f.Read(buffer)
	if n < readSize {
		err = fmt.Errorf("less than readSize")
		return
	}
	//err := binary.Read(buf, binary.LittleEndian, &pi)

	return
}

func dumpElfIdent(buffer []byte) {
	fmt.Printf("MAGIC:   0x%s\n", dumpBytes(buffer[0:4], ",0x"))
	fmt.Printf("CLASS:   %s(0x%02X)\n", eiClass[int(buffer[4])], int(buffer[4]))
	fmt.Printf("DATA:    %s(0x%02X)\n", eiData[int(buffer[5])], int(buffer[5]))
	fmt.Printf("VERSION: 0x%02X\n", buffer[6])
	fmt.Printf("PAD:     0x%s\n", dumpBytes(buffer[7:16], ",0x"))
}

*/

/*
https://refspecs.linuxfoundation.org/elf/

https://sugawarayusuke.hatenablog.com/entry/2017/04/09/213133

https://docs.oracle.com/cd/E19683-01/817-4912/6mkdg542u/index.html

http://caspar.hazymoon.jp/OpenBSD/annex/elf.html
*/
