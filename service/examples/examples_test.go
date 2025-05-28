// Copyright 2025 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package examples_test

import (
	"fmt"
	"testing"

	"github.com/openconfig/attestz/service/examples"
)

func Test_PCRQuoteDigest(t *testing.T) {
	// The PCR quote digest is calculated from the sorted *returned* PCR's.
	// These are the PCR values requested in an Attestz request and returned
	// in an Attestz response. (i.e. the map<int32, bytes> pcr_values = 3; field
	// in the Attestz response, sorted.
	pcrs := []examples.PCR{
		{
			Index: 0,
			Value: []byte("2cec31ce9b099c75de27d9825e9291e2e4fa0e5be320425b5c202fa8c1cb78b5"),
		},
		{
			Index: 1,
			Value: []byte("104fab1de5741fbdc3c04f13588eef8ecf1573abb91bdbc66aa237d8f2f1d1a1"),
		},
		{
			Index: 2,
			Value: []byte("cdf84b6d8b7aee8363dd0895e70d91da6f6e5c347d7f8105ae820ef133260dbe"),
		},
		{
			Index: 3,
			Value: []byte("66e762044bcba730a19b7d0154dbac5c191ace8660f2b5424785c7b82b2de290"),
		},
		{
			Index: 4,
			Value: []byte("4a51aca5d25bcfdcde87b6dae630271b0e84db23fbfbae3fce24e2e22f750470"),
		},
	}
	print(fmt.Sprintf("%x\n", examples.Digest(pcrs)))
}
