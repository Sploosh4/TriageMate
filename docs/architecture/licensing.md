# Licensing and redistribution

TriageMate's owner has selected GNU General Public License version 3 only for the current first-party project. The SPDX identifier is `GPL-3.0-only`; this deliberately does not grant an automatic option to use a future GPL version. The canonical [LICENSE](../../LICENSE) remains verbatim, including its generic appendix examples. [NOTICE](../../NOTICE) states the project's specific version choice and warranty notice. [SPDX](https://spdx.org/licenses/GPL-3.0-only.html) explains the distinction from `GPL-3.0-or-later`.

The repository's current first-party copyright notice identifies Sploosh4. Its local reachable history records the author labels `jpc` and `Sploosh4`; those labels are not independently verified copyright assignments or a comprehensive provenance audit. The change follows the owner's direct instruction and the reviewed upstream grants, rather than assuming repository ownership transfers third-party copyright. No separately identified incompatible first-party notice was found in the current code. Historical imported data/model rights remain unverified and are not granted by this project license.

Earlier valid licenses remain effective for copies received under them; changing the current project license does not revoke prior grants or rewrite historical commits. GPL compatibility permits a combined work under GPLv3 while original upstream terms and attribution still apply. The preserved [Apache-2.0 text](../../LICENSES/Apache-2.0.txt) is a reference for retained grants, not a declaration that all new TriageMate code is dual-licensed. Apache explicitly documents [GPLv3 derivative compatibility](https://www.apache.org/licenses/GPL-compatibility.html).

## Dependencies and notices

The locked frontend runtime closure contains 17 MIT packages; their verbatim license/copyright texts remain in the [frontend notices](../ui/engine/FrontendThirdPartyNotices.txt). The native parser retains its PostgreSQL, BSD-2-Clause, BSD-3-Clause and xxHash notices in the [parser notice](../ui/engine/ParserThirdPartyNotices.md). Neither those upstream files nor immutable database reference bytes are relabeled or rewritten by the GPL change.

The installed Python runtime closure reports MIT/MIT-0, BSD-3-Clause, ISC, PSF/Python, Apache-2.0, MPL-2.0 and LGPL terms. Notable components are cryptography (`Apache-2.0 OR BSD-3-Clause`), certifi (`MPL-2.0`) and psycopg2 (LGPL version 3 or later with its documented exceptions). These keep their own licenses. Metadata review found no incompatible declared runtime license; it is not an exhaustive file-level audit of every native wheel or operating-system image component. Mozilla documents [MPL/GPL combinations and retained source obligations](https://www.mozilla.org/en-US/MPL/2.0/FAQ/), and the [GNU license guidance](https://www.gnu.org/licenses/license-list.html) describes compatibility for the other families.

## Source and binary distribution

Distribute the applicable license, copyright and third-party notices with source. Binary/image distribution must also provide the corresponding source and build/install scripts for the exact distributed version, and satisfy dependency-specific source, notice and relinking obligations. A mutable branch URL alone is not evidence that an exact binary's corresponding source is available. See [GPLv3 sections 4–6](https://spdx.org/licenses/GPL-3.0-only.html). No image-registry publication or distribution-compliance certification is performed by this local license edit.

Public-feed observations and reference datasets retain their upstream rights and terms independently. Historical large snapshots, serialized models, private-identifier exposure and GitHub-hosted logs/artifacts require publication review; current secret-pattern checks do not clear those areas. A valid permissive upstream grant can suffice without seeking new consent from every contributor, but unlicensed or incompatibly licensed material must not be silently included.

## Contributions

Contributions to current first-party TriageMate should be made under `GPL-3.0-only`, with the contributor's right to submit them. Identify copied or adapted upstream material and retain its original notices and compatible grant. Do not submit operator credentials, private evidence or material whose redistribution rights are unknown. This policy does not retroactively establish rights for historical submissions.
