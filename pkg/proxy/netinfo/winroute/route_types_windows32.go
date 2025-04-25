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

//go:build 386 && windows

package winroute

// mibIPforwardTable2 structure contains a table of IP route entries.
// https://learn.microsoft.com/en-us/windows/win32/api/netioapi/ns-netioapi-mib_ipforward_table2
type mibIPforwardTable2 struct {
	numEntries uint32
	_          [4]byte
	table      [anySize]MibIPforwardRow2
}
