# Third-party notices

## Chromium

Portions of the FIDO hybrid implementation are Swift ports of behavior from
Chromium revision `535b82484305ec03127bbe951212f6afdec72a43`. Exact source
files, blob hashes, destination mappings, and dispositions are recorded in
`References/upstream-inventory.json` and `EXPERIMENTS.md`.

Copyright 2020 The Chromium Authors. All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice,
   this list of conditions and the following disclaimer.
2. Redistributions in binary form must reproduce the above copyright notice,
   this list of conditions and the following disclaimer in the documentation
   and/or other materials provided with the distribution.
3. Neither the name of Google Inc. nor the names of its contributors may be
   used to endorse or promote products derived from this software without
   specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR
ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

## swift-url

Origin parsing and IDNA normalization use the exact `swift-url` 0.4.2 package
revision `9306a962396a50d7d88e924afcd7ec67226763db`. That dependency is licensed
under Apache License 2.0 and retains its own `LICENSE` file in the resolved
SwiftPM source package. Exact revision and license hashes are recorded in
`References/upstream-lock.json`.

Copyright The swift-url Contributors.

Licensed under the Apache License, Version 2.0. You may obtain a copy at
<https://www.apache.org/licenses/LICENSE-2.0>.

SwiftPM also resolves swift-system 1.8.1 as an unlinked transitive package of
swift-url. It is licensed under Apache License 2.0 and retains its own license
in the resolved source package; its exact revision is recorded in the lock.

## Public Suffix List

`Sources/SiriusSecurityKey/Resources/effective_tld_names.dat` is the exact
Chromium-pinned Public Suffix List source blob recorded in
`References/upstream-lock.json`. It includes ICANN and private rules and is
licensed under the Mozilla Public License, version 2.0.

This Source Code Form is subject to the terms of the Mozilla Public License,
v. 2.0. If a copy of the MPL was not distributed with this file, one is
available at <https://mozilla.org/MPL/2.0/>.
