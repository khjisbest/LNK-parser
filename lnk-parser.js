class LNKParser {
    constructor(arrayBuffer) {
        this.buffer = new DataView(arrayBuffer);
        this.offset = 0;
        this.data = {};
    }

    canRead(length) {
        return this.offset + length <= this.buffer.byteLength;
    }

    readUInt32() {
        if (!this.canRead(4)) throw new Error(`Cannot read UInt32 at 0x${this.offset.toString(16)}`);
        const value = this.buffer.getUint32(this.offset, true);
        this.offset += 4;
        return value;
    }

    readUInt16() {
        if (!this.canRead(2)) throw new Error(`Cannot read UInt16 at 0x${this.offset.toString(16)}`);
        const value = this.buffer.getUint16(this.offset, true);
        this.offset += 2;
        return value;
    }

    readUInt8() {
        if (!this.canRead(1)) throw new Error(`Cannot read UInt8 at 0x${this.offset.toString(16)}`);
        return this.buffer.getUint8(this.offset++);
    }

    readBytes(length) {
        if (!this.canRead(length)) throw new Error(`Cannot read ${length} bytes at 0x${this.offset.toString(16)}`);
        const bytes = new Uint8Array(this.buffer.buffer, this.offset, length);
        this.offset += length;
        return bytes;
    }

    readString(length) {
        if (length === 0) return '';
        const bytes = this.readBytes(length);
        return new TextDecoder('utf-8', { fatal: false }).decode(bytes);
    }

    readWString(length) {
        if (length === 0) return '';
        if (!this.canRead(length * 2)) throw new Error(`Cannot read ${length} wchars at 0x${this.offset.toString(16)}`);
        let str = '';
        for (let i = 0; i < length; i++) {
            const code = this.readUInt16();
            if (code === 0) break;
            str += String.fromCharCode(code);
        }
        return str;
    }

    skip(length) {
        if (!this.canRead(length)) throw new Error(`Cannot skip ${length} bytes at 0x${this.offset.toString(16)}`);
        this.offset += length;
    }

    readFileTime() {
        if (!this.canRead(8)) return null;
        const low = this.readUInt32();
        const high = this.readUInt32();
        const filetime = (high >>> 0) * 4294967296 + (low >>> 0);

        if (filetime === 0) return null;

        const EPOCH_DIFF = 116444736000000000;
        const timestamp = (filetime - EPOCH_DIFF) / 10000;

        if (timestamp < 0) return null;

        try {
            return new Date(timestamp).toISOString();
        } catch (e) {
            return null;
        }
    }

    parse() {
        if (this.buffer.byteLength < 76) {
            throw new Error('File too small (minimum 76 bytes)');
        }

        this.parseHeader();
        this.parseOptionalData();
        this.parseExtraData();

        return this.data;
    }

    parseHeader() {
        const signature = this.readUInt32();
        if (signature !== 0x4C) {
            throw new Error(`Invalid LNK signature: 0x${signature.toString(16)}`);
        }

        this.skip(16); // GUID

        const linkFlags = this.readUInt32();
        this.data.flags = this.parseLinkFlags(linkFlags);

        const fileAttributes = this.readUInt32();
        this.data.attributes = this.parseFileAttributes(fileAttributes);

        this.data.creationTime = this.readFileTime();
        this.data.accessTime = this.readFileTime();
        this.data.writeTime = this.readFileTime();

        this.data.fileSize = this.readUInt32();
        this.data.iconIndex = this.readUInt32();

        const showCommand = this.readUInt32();
        this.data.showCommand = this.parseShowCommand(showCommand);

        this.skip(2); // HotKey
        this.skip(10); // Reserved
    }

    parseOptionalData() {
        const flags = this.data.flags;

        if (flags.HasLinkTargetIDList) {
            this.parseLinkTargetIDList();
        }

        if (flags.HasLinkInfo) {
            this.parseLinkInfo();
        }

        if (flags.HasName) {
            const name = this.readStringData();
            if (name) this.data.name = name;
        }

        if (flags.HasRelativePath) {
            const path = this.readStringData();
            if (path) this.data.relativePath = path;
        }

        if (flags.HasWorkingDir) {
            const dir = this.readStringData();
            if (dir) this.data.workingDir = dir;
        }

        if (flags.HasArguments) {
            const args = this.readStringData();
            if (args) this.data.commandLine = args;
        }

        if (flags.HasIconLocation) {
            const icon = this.readStringData();
            if (icon) this.data.iconLocation = icon;
        }
    }

    readStringData() {
        try {
            const countCharacters = this.readUInt16();
            if (countCharacters === 0) return '';

            let str = '';
            for (let i = 0; i < countCharacters; i++) {
                const code = this.readUInt16();
                if (code === 0) break;
                str += String.fromCharCode(code);
            }
            return str;
        } catch (e) {
            return '';
        }
    }

    parseLinkTargetIDList() {
        try {
            const size = this.readUInt16();
            const startOffset = this.offset;

            while (this.offset - startOffset < size - 2) {
                if (!this.canRead(2)) break;
                const itemSize = this.readUInt16();
                if (itemSize === 0) break;
                this.skip(itemSize - 2);
            }
        } catch (e) {
            // Ignore errors
        }
    }

    parseLinkInfo() {
        try {
            const startOffset = this.offset;
            const size = this.readUInt32();
            const headerSize = this.readUInt32();

            const flags = this.readUInt32();
            const volumeIDOffset = this.readUInt32();
            const localBasePathOffset = this.readUInt32();
            const commonNetworkOffset = this.readUInt32();
            const commonPathSuffixOffset = this.readUInt32();

            if (headerSize > 28) this.readUInt32(); // LocalBasePathOffsetUnicode
            if (headerSize > 32) this.readUInt32(); // CommonPathSuffixOffsetUnicode

            if (flags & 1) { // VolumeIDAndLocalBasePath
                this.offset = startOffset + volumeIDOffset;
                this.parseVolumeID();

                if (localBasePathOffset > 0) {
                    this.offset = startOffset + localBasePathOffset;
                    const path = this.readNullTerminatedString();
                    if (path) this.data.localBasePath = path;
                }

                if (commonPathSuffixOffset > 0) {
                    this.offset = startOffset + commonPathSuffixOffset;
                    const suffix = this.readNullTerminatedString();
                    if (suffix) this.data.commonPathSuffix = suffix;
                }
            }

            this.offset = startOffset + size;
        } catch (e) {
            // Ignore errors
        }
    }

    parseVolumeID() {
        try {
            const size = this.readUInt32();
            const driveType = this.readUInt32();
            const serialNumber = this.readUInt32();
            const volumeLabelOffset = this.readUInt32();

            if (volumeLabelOffset === 0x14) {
                this.readUInt32(); // VolumeLabelOffsetUnicode
            }

            const startOffset = this.offset - 16;
            if (volumeLabelOffset > 0) {
                this.offset = startOffset + volumeLabelOffset;
                const label = this.readNullTerminatedString();
                if (label) this.data.volumeLabel = label;
            }
        } catch (e) {
            // Ignore errors
        }
    }

    readNullTerminatedString() {
        let str = '';
        while (this.canRead(1)) {
            const byte = this.readUInt8();
            if (byte === 0) break;
            if (byte >= 32 && byte <= 126) {
                str += String.fromCharCode(byte);
            }
        }
        return str;
    }

    parseExtraData() {
        this.data.extraDataBlocks = [];

        while (this.offset < this.buffer.byteLength - 4) {
            if (!this.canRead(8)) break;

            const size = this.readUInt32();
            if (size < 8 || size > 10000000) break;

            if (this.offset + size - 4 > this.buffer.byteLength) break;

            const signature = this.readUInt32();
            const dataStart = this.offset;
            const dataEnd = dataStart + (size - 8);

            this.parseExtraDataBlock(signature, size - 8, dataStart);

            this.offset = dataEnd;
        }
    }

    parseExtraDataBlock(signature, dataSize, dataStart) {
        try {
            const data = this.buffer.buffer.slice(dataStart, dataStart + dataSize);
            const dataView = new DataView(data);
            const blockName = this.getBlockName(signature);

            switch (signature) {
                case 0xA0000001: // EnvironmentVariableDataBlock
                    this.parseEnvironmentVariableBlock(dataView);
                    break;
                case 0xA0000002: // ConsoleDataBlock
                    this.parseConsoleBlock(dataView);
                    break;
                case 0xA0000003: // TrackerDataBlock
                    break;
                case 0xA0000004: // ConsoleFEDataBlock
                    break;
                case 0xA0000005: // SpecialFolderDataBlock
                    break;
                case 0xA0000006: // DarwinDataBlock
                    this.parseDarwinBlock(dataView);
                    break;
                case 0xA0000007: // IconEnvironmentDataBlock
                    this.parseIconEnvironmentBlock(dataView);
                    break;
            }

            // Store block info
            this.data.extraDataBlocks.push({
                signature: `0x${signature.toString(16).padStart(8, '0').toUpperCase()}`,
                name: blockName,
                size: dataSize
            });
        } catch (e) {
            // Ignore errors
        }
    }

    parseEnvironmentVariableBlock(dataView) {
        if (dataView.byteLength < 260) return;

        let str = '';
        for (let i = 0; i < 260; i++) {
            const byte = dataView.getUint8(i);
            if (byte === 0) break;
            if (byte >= 32 && byte <= 126) str += String.fromCharCode(byte);
        }

        if (str && str.length > 3) {
            if (!this.data.envVariable) this.data.envVariable = str;
        }
    }

    parseDarwinBlock(dataView) {
        if (dataView.byteLength < 260) return;

        let str = '';
        for (let i = 0; i < 260; i++) {
            const byte = dataView.getUint8(i);
            if (byte === 0) break;
            if (byte >= 32 && byte <= 126) str += String.fromCharCode(byte);
        }

        if (str && str.length > 3 && !this.data.commandLine) {
            this.data.commandLine = str;
        }
    }

    parseIconEnvironmentBlock(dataView) {
        if (dataView.byteLength < 260) return;

        let str = '';
        for (let i = 0; i < 260; i++) {
            const byte = dataView.getUint8(i);
            if (byte === 0) break;
            if (byte >= 32 && byte <= 126) str += String.fromCharCode(byte);
        }

        if (str && str.length > 3) {
            this.data.iconEnvironment = str;
        }
    }

    parseConsoleBlock(dataView) {
        // ConsoleDataBlock starts with FillAttributes, PopupFillAttributes, etc.
        // Skip to end and check for any strings
        try {
            for (let i = 0; i < Math.min(dataView.byteLength, 200); i++) {
                const byte = dataView.getUint8(i);
                if (byte >= 32 && byte <= 126) {
                    let str = '';
                    for (let j = i; j < dataView.byteLength && j < i + 256; j++) {
                        const b = dataView.getUint8(j);
                        if (b >= 32 && b <= 126) str += String.fromCharCode(b);
                        else if (str.length > 10) break;
                    }
                    if (str.length > 10 && !this.data.commandLine) {
                        this.data.commandLine = str;
                        break;
                    }
                }
            }
        } catch (e) {
            // Ignore
        }
    }

    getBlockName(signature) {
        const names = {
            0xA0000001: 'EnvironmentVariableDataBlock',
            0xA0000002: 'ConsoleDataBlock',
            0xA0000003: 'TrackerDataBlock',
            0xA0000004: 'ConsoleFEDataBlock',
            0xA0000005: 'SpecialFolderDataBlock',
            0xA0000006: 'DarwinDataBlock',
            0xA0000007: 'IconEnvironmentDataBlock',
            0xA0000008: 'ShimDataBlock',
            0xA0000009: 'PropertyStoreDataBlock',
            0xA000000A: 'VistaAndAboveIDListDataBlock',
            0xA000000B: 'KnownFolderDataBlock'
        };
        return names[signature] || 'UnknownDataBlock';
    }

    parseLinkFlags(flags) {
        return {
            HasLinkTargetIDList: (flags & 0x00000001) !== 0,
            HasLinkInfo: (flags & 0x00000002) !== 0,
            HasName: (flags & 0x00000004) !== 0,
            HasRelativePath: (flags & 0x00000008) !== 0,
            HasWorkingDir: (flags & 0x00000010) !== 0,
            HasArguments: (flags & 0x00000020) !== 0,
            HasIconLocation: (flags & 0x00000040) !== 0,
            IsUnicode: (flags & 0x00000080) !== 0,
            ForceNoLinkInfo: (flags & 0x00000100) !== 0,
            HasExpString: (flags & 0x00000200) !== 0,
            RunInSeparateProcess: (flags & 0x00000400) !== 0,
            HasDarwinID: (flags & 0x00001000) !== 0,
            RunAsUser: (flags & 0x00002000) !== 0,
            HasExpIcon: (flags & 0x00004000) !== 0,
            NoPidlAlias: (flags & 0x00008000) !== 0
        };
    }

    parseFileAttributes(attr) {
        const attrs = [];
        if (attr & 0x00000001) attrs.push('READONLY');
        if (attr & 0x00000002) attrs.push('HIDDEN');
        if (attr & 0x00000004) attrs.push('SYSTEM');
        if (attr & 0x00000020) attrs.push('ARCHIVE');
        if (attr & 0x00000080) attrs.push('NORMAL');
        if (attr & 0x00000100) attrs.push('TEMPORARY');
        if (attr & 0x00000400) attrs.push('COMPRESSED');
        if (attr & 0x00001000) attrs.push('OFFLINE');
        if (attr & 0x00002000) attrs.push('NOT_INDEXED');
        if (attr & 0x00004000) attrs.push('ENCRYPTED');
        return attrs.length > 0 ? attrs.join(' | ') : 'NORMAL';
    }

    parseShowCommand(cmd) {
        const commands = {
            0: 'Hide',
            1: 'Normal',
            3: 'Maximized',
            7: 'Minimized'
        };
        return commands[cmd] || `Unknown (${cmd})`;
    }
}

// UI
const fileInput = document.getElementById('fileInput');
const resultsContainer = document.getElementById('resultsContainer');
const errorContainer = document.getElementById('errorContainer');

fileInput.addEventListener('change', (e) => {
    if (e.target.files.length > 0) {
        handleFile(e.target.files[0]);
    }
});

function handleFile(file) {
    const reader = new FileReader();
    reader.onload = (e) => {
        try {
            const buffer = e.target.result;

            if (buffer.byteLength < 4) {
                showError('File too small');
                return;
            }

            const view = new DataView(buffer);
            const sig = view.getUint32(0, true);
            if (sig !== 0x4C) {
                showError(`Invalid LNK signature: 0x${sig.toString(16)}`);
                return;
            }

            const parser = new LNKParser(buffer);
            const data = parser.parse();
            displayResults(data);
        } catch (error) {
            showError(error.message);
        }
    };
    reader.readAsArrayBuffer(file);
}

function displayResults(data) {
    errorContainer.innerHTML = '';
    resultsContainer.innerHTML = '';

    let html = '<div class="section">';
    html += '<div class="section-title">HEADER</div>';
    html += rowHtml('CreationTime', data.creationTime || 'N/A');
    html += rowHtml('AccessTime', data.accessTime || 'N/A');
    html += rowHtml('WriteTime', data.writeTime || 'N/A');
    html += rowHtml('FileSize', data.fileSize + ' bytes');
    html += rowHtml('IconIndex', data.iconIndex);
    html += rowHtml('ShowCommand', data.showCommand);
    html += '</div>';

    html += '<div class="section">';
    html += '<div class="section-title">FLAGS</div>';
    if (data.flags) {
        Object.entries(data.flags).forEach(([key, value]) => {
            if (value) html += rowHtml(key, 'YES');
        });
    }
    html += '</div>';

    if (data.localBasePath) {
        html += '<div class="section">';
        html += '<div class="section-title">LINK INFO</div>';
        html += rowHtml('LocalBasePath', data.localBasePath);
        if (data.volumeLabel) html += rowHtml('VolumeLabel', data.volumeLabel);
        if (data.commonPathSuffix) html += rowHtml('CommonPathSuffix', data.commonPathSuffix);
        html += '</div>';
    }

    if (data.name) html += '<div class="section">' + '<div class="section-title">NAME</div>' + rowHtml('Value', data.name) + '</div>';
    if (data.relativePath) html += '<div class="section">' + '<div class="section-title">RELATIVE_PATH</div>' + rowHtml('Value', data.relativePath) + '</div>';
    if (data.workingDir) html += '<div class="section">' + '<div class="section-title">WORKING_DIR</div>' + rowHtml('Value', data.workingDir) + '</div>';

    if (data.commandLine) {
        html += '<div class="section">';
        html += '<div class="section-title">COMMAND_LINE_ARGUMENTS</div>';
        html += rowHtml('Value', data.commandLine);
        html += '</div>';
    }

    if (data.iconLocation) html += '<div class="section">' + '<div class="section-title">ICON_LOCATION</div>' + rowHtml('Value', data.iconLocation) + '</div>';

    if (data.extraDataBlocks && data.extraDataBlocks.length > 0) {
        html += '<div class="section">';
        html += '<div class="section-title">EXTRA_DATA_BLOCKS</div>';
        data.extraDataBlocks.forEach(block => {
            html += rowHtml(block.name, `${block.signature} (${block.size} bytes)`);
        });
        html += '</div>';
    }

    resultsContainer.innerHTML = html;
}

function rowHtml(label, value) {
    return `<div class="row">
        <div class="label">${label}</div>
        <div class="value">${escapeHtml(String(value))}</div>
    </div>`;
}

function showError(msg) {
    errorContainer.innerHTML = `<div class="error">${escapeHtml(msg)}</div>`;
    resultsContainer.innerHTML = '';
}

function clearResults() {
    fileInput.value = '';
    resultsContainer.innerHTML = '';
    errorContainer.innerHTML = '';
}

function escapeHtml(text) {
    const map = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#039;' };
    return text.replace(/[&<>"']/g, m => map[m]);
}
