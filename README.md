Copyright © 2020 ThreatConnect, Inc. All rights reserved.
Contributor: Cezanne Vahid
Software License
Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:
Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.
Neither the name of ThreatConnect, Inc. nor the names of its contributors may be used to endorse or promote products derived from this software without specific prior written permission.
THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

---
A collection of code that I wrote at during my employment at ThreatConnect, intended mainly for reference. If interested in using any of the code in this repo, please contact me.

#### attack_script
A script to ingest data from MITRE ATT&CK into ThreatConnect

#### rule_sync
Main logic of app built to synchronize ThreatConnect organization's signatures with hunting rules stored at VirusTotal

#### tc_dm
A handy tool I wrote that takes a mapping JSON file and arbitrary JSON data (say from VirusTotal) and performs data mappings to create new JSON batch file accepted by ThreatConnect

#### vt_mappings
A mapping JSON to map data from VT to TC's data model

#### notification_sync
Main logic of app built to synchronize ThreatConnect organization's incidents with hunting notifications stored at VirusTotal, using data mapping tool
