//  Copyright 2024 Google LLC
//
//  Licensed under the Apache License, Version 2.0 (the "License");
//  you may not use this file except in compliance with the License.
//  You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
//  Unless required by applicable law or agreed to in writing, software
//  distributed under the License is distributed on an "AS IS" BASIS,
//  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//  See the License for the specific language governing permissions and
//  limitations under the License.

// Code from https://github.com/GoogleCloudPlatform/google-guest-agent

//go:build windows

package winroute

import (
	"fmt"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	// modiphlpapi is the module handle for iphlpapi.dll.
	modiphlpapi = windows.NewLazySystemDLL("iphlpapi.dll")
	// https://learn.microsoft.com/en-us/windows/win32/api/netioapi/nf-netioapi-createipforwardentry2
	procCreateIPForwardEntry2 = modiphlpapi.NewProc("CreateIpForwardEntry2")
	// https://learn.microsoft.com/en-us/windows/win32/api/netioapi/nf-netioapi-deleteipforwardentry2
	procDeleteIPForwardEntry2 = modiphlpapi.NewProc("DeleteIpForwardEntry2")
	// https://learn.microsoft.com/en-us/windows/win32/api/netioapi/nf-netioapi-freemibtable
	procFreeMibTable = modiphlpapi.NewProc("FreeMibTable")
	// https://learn.microsoft.com/en-us/windows/win32/api/netioapi/nf-netioapi-getipforwardtable2
	procGetIPForwardTable2 = modiphlpapi.NewProc("GetIpForwardTable2")
)

// freeMibTable frees the memory allocated by GetIpForwardTable2.
func freeMibTable(table *mibIPforwardTable2) {
	syscall.SyscallN(procFreeMibTable.Addr(), uintptr(unsafe.Pointer(table)))
}

func syscallError(r0 uintptr, errNo syscall.Errno, msg string) error {
	if r0 == 0 && errNo != 0 {
		return fmt.Errorf("%s: %s", msg, errNo.Error())
	} else if r0 != 0 {
		return syscall.Errno(r0)
	}
	return nil
}

// getIPForwardTable2 returns the IP forward table.
func getIPForwardTable2(family AddressFamily) ([]MibIPforwardRow2, error) {
	var table *mibIPforwardTable2

	r0, _, errNo := syscall.SyscallN(procGetIPForwardTable2.Addr(), uintptr(family), uintptr(unsafe.Pointer(&table)))
	if err := syscallError(r0, errNo, "GetIpForwardTable2"); err != nil {
		return nil, err
	}

	res := append(make([]MibIPforwardRow2, 0, table.numEntries), table.readTable()...)
	table.free()

	return res, nil
}

// createIPForwardEntry2 creates an IP forward entry.
func createIPForwardEntry2(route *MibIPforwardRow2) error {
	r0, _, errNo := syscall.SyscallN(procCreateIPForwardEntry2.Addr(), uintptr(unsafe.Pointer(route)))
	if err := syscallError(r0, errNo, "CreateIPForwardEntry2"); err != nil {
		return err
	}
	return nil
}

// deleteIPForwardEntry2 deletes an IP forward entry.
func deleteIPForwardEntry2(route *MibIPforwardRow2) error {
	r0, _, errNo := syscall.SyscallN(procDeleteIPForwardEntry2.Addr(), uintptr(unsafe.Pointer(route)))
	if err := syscallError(r0, errNo, "DeleteIPForwardEntry2"); err != nil {
		return err
	}
	return nil
}
