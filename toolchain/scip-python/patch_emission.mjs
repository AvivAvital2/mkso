import fs from "node:fs";
import path from "node:path";

const sourceRoot = process.argv[2];
if (!sourceRoot) {
    throw new Error(
        "usage: node patch_emission.mjs SCIP_PYTHON_SOURCE_ROOT [patch4|patch2-negative-control]"
    );
}
const patchMode = process.argv[3] ?? "patch4";
if (!new Set(["patch4", "patch2-negative-control"]).has(patchMode)) {
    throw new Error(`unsupported patch mode: ${patchMode}`);
}

function replaceExactly(relativePath, before, after, expectedCount = 1) {
    const target = path.join(sourceRoot, relativePath);
    const original = fs.readFileSync(target, "utf8");
    const actualCount = original.split(before).length - 1;
    if (actualCount !== expectedCount) {
        throw new Error(
            `${relativePath}: expected ${expectedCount} exact patch anchors, found ${actualCount}`
        );
    }
    fs.writeFileSync(target, original.replaceAll(before, after));
}

const treeVisitor = "packages/pyright-scip/src/treeVisitor.ts";
const scipBinding = "packages/pyright-scip/src/scip.ts";
const indexer = "packages/pyright-scip/src/indexer.ts";

// Upstream's checked-in binding predates SCIP 0.9's required per-document
// position encoding. Extend that binding at the source boundary so the native
// producer can emit field 6. This remains standard SCIP protobuf; no emitted
// index is post-processed.
replaceExactly(
    scipBinding,
    `    export enum TextEncoding {
        UnspecifiedTextEncoding = 0,
        UTF8 = 1,
        UTF16 = 2,
    }
`,
    `    export enum TextEncoding {
        UnspecifiedTextEncoding = 0,
        UTF8 = 1,
        UTF16 = 2,
    }
    export enum PositionEncoding {
        UnspecifiedPositionEncoding = 0,
        UTF8CodeUnitOffsetFromLineStart = 1,
        UTF16CodeUnitOffsetFromLineStart = 2,
        UTF32CodeUnitOffsetFromLineStart = 3,
    }
`
);

replaceExactly(
    scipBinding,
    `                      symbols?: SymbolInformation[];
                      text?: string;
                  }
`,
    `                      symbols?: SymbolInformation[];
                      text?: string;
                      position_encoding?: PositionEncoding;
                  }
`
);

replaceExactly(
    scipBinding,
    `                if ('text' in data && data.text != undefined) {
                    this.text = data.text;
                }
`,
    `                if ('text' in data && data.text != undefined) {
                    this.text = data.text;
                }
                if ('position_encoding' in data && data.position_encoding != undefined) {
                    this.position_encoding = data.position_encoding;
                }
`
);

replaceExactly(
    scipBinding,
    `        set text(value: string) {
            pb_1.Message.setField(this, 5, value);
        }
`,
    `        set text(value: string) {
            pb_1.Message.setField(this, 5, value);
        }
        get position_encoding() {
            return pb_1.Message.getFieldWithDefault(
                this,
                6,
                PositionEncoding.UnspecifiedPositionEncoding
            ) as PositionEncoding;
        }
        set position_encoding(value: PositionEncoding) {
            pb_1.Message.setField(this, 6, value);
        }
`
);

replaceExactly(
    scipBinding,
    `            symbols?: ReturnType<typeof SymbolInformation.prototype.toObject>[];
            text?: string;
        }): Document {
`,
    `            symbols?: ReturnType<typeof SymbolInformation.prototype.toObject>[];
            text?: string;
            position_encoding?: PositionEncoding;
        }): Document {
`
);

replaceExactly(
    scipBinding,
    `            if (data.text != null) {
                message.text = data.text;
            }
            return message;
`,
    `            if (data.text != null) {
                message.text = data.text;
            }
            if (data.position_encoding != null) {
                message.position_encoding = data.position_encoding;
            }
            return message;
`
);

replaceExactly(
    scipBinding,
    `                symbols?: ReturnType<typeof SymbolInformation.prototype.toObject>[];
                text?: string;
            } = {};
`,
    `                symbols?: ReturnType<typeof SymbolInformation.prototype.toObject>[];
                text?: string;
                position_encoding?: PositionEncoding;
            } = {};
`
);

replaceExactly(
    scipBinding,
    `            if (this.text != null) {
                data.text = this.text;
            }
            return data;
`,
    `            if (this.text != null) {
                data.text = this.text;
            }
            if (this.position_encoding != null) {
                data.position_encoding = this.position_encoding;
            }
            return data;
`
);

replaceExactly(
    scipBinding,
    `            if (this.text.length) writer.writeString(5, this.text);
            if (!w) return writer.getResultBuffer();
`,
    `            if (this.text.length) writer.writeString(5, this.text);
            if (this.position_encoding)
                writer.writeEnum(6, this.position_encoding);
            if (!w) return writer.getResultBuffer();
`
);

replaceExactly(
    scipBinding,
    `                    case 5:
                        message.text = reader.readString();
                        break;
                    default:
`,
    `                    case 5:
                        message.text = reader.readString();
                        break;
                    case 6:
                        message.position_encoding = reader.readEnum();
                        break;
                    default:
`
);

replaceExactly(
    indexer,
    `                let doc = new scip.Document({
                    relative_path: path.relative(this.getProjectRoot(), filepath),
                });
`,
    `                let doc = new scip.Document({
                    language: 'Python',
                    relative_path: path.relative(this.getProjectRoot(), filepath),
                    position_encoding: scip.PositionEncoding.UTF16CodeUnitOffsetFromLineStart,
                });
`
);

replaceExactly(
    treeVisitor,
    `    override visitImportFrom(node: ImportFromNode): boolean {
        const symbol = this.getScipSymbol(node);
`,
    `    override visitImportFrom(node: ImportFromNode): boolean {
        const pythonPackage = this.moduleNameNodeToPythonPackage(node.module);
        if (!pythonPackage) {
            throw new Error(\`Unable to resolve imported module: \${_formatModuleName(node.module)}\`);
        }
        const symbol = Symbols.makeModuleInit(pythonPackage, _formatModuleName(node.module));
`
);

replaceExactly(
    treeVisitor,
    `        const symbolPackage = this.moduleNameNodeToPythonPackage(node.module);
        if (symbolPackage === this.stdlibPackage) {
            this.emitExternalSymbolInformation(node.module, symbol, []);
        }
`,
    `        this.emitExternalSymbolInformation(node.module, symbol, []);
`
);

replaceExactly(
    treeVisitor,
    `            let symbol = this.getFunctionSymbol(superDecl);
            if (!symbol.isLocal()) {
                relationshipMap.set(
`,
    `            let symbol = this.getFunctionSymbol(superDecl);
            if (!symbol.isLocal()) {
                this.ensureExternalSymbolInformation(symbol);
                relationshipMap.set(
`
);

replaceExactly(
    treeVisitor,
    `                                const symbol = Symbols.makeClass(
                                    pythonPackage,
                                    base.details.moduleName,
                                    base.details.name
                                ).value;

                                return new scip.Relationship({
                                    symbol,
`,
    `                                const symbol = Symbols.makeClass(
                                    pythonPackage,
                                    base.details.moduleName,
                                    base.details.name
                                );
                                this.ensureExternalSymbolInformation(symbol);

                                return new scip.Relationship({
                                    symbol: symbol.value,
`
);

replaceExactly(
    treeVisitor,
    `        softAssert(symbol.value.trim() == symbol.value, \`Invalid symbol \${node} -> \${symbol.value}\`);

        this.document.occurrences.push(
`,
    `        softAssert(symbol.value.trim() == symbol.value, \`Invalid symbol \${node} -> \${symbol.value}\`);

        if ((role & scip.SymbolRole.Definition) !== 0) {
            this.ensureDefinitionSymbolInformation(node, symbol);
        } else {
            this.emitExternalSymbolInformation(node, symbol, []);
        }

        this.document.occurrences.push(
`
);

replaceExactly(
    treeVisitor,
    `        const declModuleName = _formatModuleName(node);
        return this.guessPackage(declModuleName, decl ? decl.path : undefined);
`,
    `        const declModuleName = _formatModuleName(node);
        const importInfo = getImportInfo(node);
        const resolvedImportPath = importInfo?.resolvedPaths.find((resolvedPath) => resolvedPath.length !== 0);
        return this.guessPackage(declModuleName, decl ? decl.path : resolvedImportPath);
`
);

replaceExactly(
    treeVisitor,
    `    private getIntrinsicSymbol(_node: ParseNode): ScipSymbol {
        // return this.makeLsifSymbol(this._stdlibPackage, 'intrinsics', node);

        // TODO: Should these not be locals?
        return ScipSymbol.local(this.counter.next());
    }
`,
    `    private getIntrinsicSymbol(node: ParseNode): ScipSymbol {
        const name = (node as NameNode).value;
        return Symbols.makeTerm(Symbols.makeModule(this.stdlibPackage, 'builtins'), name);
    }
`
);

replaceExactly(
    treeVisitor,
    `    private emitExternalSymbolInformation(node: ParseNode, symbol: ScipSymbol, documentation: string[]) {
        if (this.externalSymbols.has(symbol.value)) {
            return;
        }

        if (documentation.length === 0) {
            const nodeFileInfo = getFileInfo(node)!;
            const hoverResult = this.program.getHoverForPosition(
                nodeFileInfo.filePath,
                convertOffsetToPosition(node.start, nodeFileInfo.lines),
                'markdown',
                _cancellationToken
            );

            if (hoverResult) {
                documentation = _formatHover(hoverResult!);
            }
        }

        if (documentation.length === 0) {
            return;
        }

        // TODO: Could consider adding the documentation finder stuff
        // from emitSymbolInformationOnce, but at this point we don't
        // need that.
        this.externalSymbols.set(
            symbol.value,
            new scip.SymbolInformation({
                symbol: symbol.value,
                documentation: documentation,
            })
        );
    }
`,
    `    private isProjectSymbol(symbol: ScipSymbol): boolean {
        return symbol.value.startsWith(Symbols.makePackage(this.projectPackage).value);
    }

    private ensureExternalSymbolInformation(symbol: ScipSymbol, documentation: string[] = []): void {
        if (symbol.isLocal() || this.isProjectSymbol(symbol) || this.externalSymbols.has(symbol.value)) {
            return;
        }

        this.externalSymbols.set(
            symbol.value,
            new scip.SymbolInformation({
                symbol: symbol.value,
                documentation,
            })
        );
    }

    private emitExternalSymbolInformation(node: ParseNode, symbol: ScipSymbol, documentation: string[]) {
        if (symbol.isLocal() || this.isProjectSymbol(symbol) || this.externalSymbols.has(symbol.value)) {
            return;
        }

        if (documentation.length === 0) {
            const nodeFileInfo = getFileInfo(node)!;
            const hoverResult = this.program.getHoverForPosition(
                nodeFileInfo.filePath,
                convertOffsetToPosition(node.start, nodeFileInfo.lines),
                'markdown',
                _cancellationToken
            );

            if (hoverResult) {
                documentation = _formatHover(hoverResult!);
            }
        }

        this.ensureExternalSymbolInformation(symbol, documentation);
    }

    private ensureDefinitionSymbolInformation(node: ParseNode, symbol: ScipSymbol): void {
        if (symbol.isLocal() || this.document.symbols.some((info) => info.symbol === symbol.value)) {
            return;
        }

        this.emitSymbolInformationOnce(node, symbol);
        if (!this.document.symbols.some((info) => info.symbol === symbol.value)) {
            this.document.symbols.push(new scip.SymbolInformation({ symbol: symbol.value }));
        }
    }
`
);

replaceExactly(
    "packages/pyright-scip/src/virtualenv/environment.ts",
    `function pipList(): PipInformation[] {
    const result = spawnSyncWithRetry(getPipCommand(), ['list', '--format=json']);

    if (result.status !== 0) {
        throw new Error(\`pip list failed with code \${result.status}: \${result.stderr}\`);
    }

    return JSON.parse(result.stdout) as PipInformation[];
}
`,
    `function pipList(): PipInformation[] {
    const script = [
        'import importlib.metadata as metadata',
        'import json',
        'items = [',
        '    {"name": dist.metadata["Name"], "version": dist.version}',
        '    for dist in metadata.distributions()',
        '    if dist.metadata["Name"]',
        ']',
        'print(json.dumps(items))',
    ].join('\\n');
    const result = spawnSyncWithRetry(getPythonCommand(), ['-c', script]);

    if (result.status !== 0) {
        throw new Error(\`Python environment query failed with code \${result.status}: \${result.stderr}\`);
    }

    return JSON.parse(result.stdout) as PipInformation[];
}
`
);

replaceExactly(
    indexer,
    "                        name: 'scip-python',\n",
    "                        name: 'mkso-scip-python',\n"
);

if (patchMode === "patch2-negative-control") {
    replaceExactly(
        "packages/pyright-scip/package.json",
        '    "version": "0.6.6",',
        '    "version": "0.6.6-mkso.2",'
    );
    replaceExactly(
        "packages/pyright-scip/package-lock.json",
        '"version": "0.6.6"',
        '"version": "0.6.6-mkso.2"',
        2
    );
    console.log("Applied mkso scip-python producer emission patch 2 negative control");
    process.exit(0);
}

replaceExactly(
    treeVisitor,
    `    ParseNode,
    ParseNodeType,
    TypeAnnotationNode,
`,
    `    ParseNode,
    ParseNodeType,
    TypeAliasNode,
    TypeAnnotationNode,
`
);

replaceExactly(
    treeVisitor,
    `    private getFunctionRelationships(node: FunctionNode): scip.Relationship[] | undefined {
`,
    `    override visitTypeAlias(node: TypeAliasNode): boolean {
        const symbol = this.getScipSymbol(node);
        this.rawSetLsifSymbol(node, symbol, false);
        this.document.symbols.push(
            new scip.SymbolInformation({
                symbol: symbol.value,
                display_name: node.name.value,
                kind: scip.SymbolInformation.Kind.TypeAlias,
            })
        );
        this.pushNewOccurrence(node.name, symbol, scip.SymbolRole.Definition);

        if (node.typeParameters) {
            this.walk(node.typeParameters);
        }
        this.walk(node.expression);
        return false;
    }

    private getFunctionRelationships(node: FunctionNode): scip.Relationship[] | undefined {
`
);

replaceExactly(
    treeVisitor,
    `            case ParseNodeType.Suite: {
`,
    `            case ParseNodeType.TypeParameter: {
                return ScipSymbol.local(this.counter.next());
            }
            case ParseNodeType.TypeAlias: {
                if (ParseTreeUtils.getEnclosingClassOrFunction(node)) {
                    return ScipSymbol.local(this.counter.next());
                }

                return Symbols.makeType(Symbols.makeModule(pythonPackage, moduleName), node.name.value);
            }
            case ParseNodeType.Suite: {
`
);

replaceExactly(
    treeVisitor,
    `    private getFunctionRelationships(node: FunctionNode): scip.Relationship[] | undefined {
`,
    `    public finalizeDocumentSymbolInformation(): void {
        const localSymbols = Array.from(
            new Set(
                this.document.occurrences
                    .map((occurrence) => occurrence.symbol)
                    .filter((symbol) => symbol.length > 0 && new ScipSymbol(symbol).isLocal())
            )
        ).sort();

        for (const symbol of localSymbols) {
            const informationCount = this.document.symbols.filter(
                (information) => information.symbol === symbol
            ).length;
            if (informationCount > 1) {
                throw new Error(\`Duplicate SymbolInformation for local occurrence symbol: \${symbol}\`);
            }
            if (informationCount === 0) {
                this.document.symbols.push(new scip.SymbolInformation({ symbol }));
            }
        }
    }

    private getFunctionRelationships(node: FunctionNode): scip.Relationship[] | undefined {
`
);

replaceExactly(
    indexer,
    `                try {
                    visitor.walk(tree);
                } catch (e) {
`,
    `                try {
                    visitor.walk(tree);
                    visitor.finalizeDocumentSymbolInformation();
                } catch (e) {
`
);

replaceExactly(
    "packages/pyright-scip/package.json",
    '    "version": "0.6.6",',
    '    "version": "0.6.6-mkso.4",'
);

replaceExactly(
    "packages/pyright-scip/package.json",
    '        "diff": "^5.0.0",',
    '        "diff": "5.2.2",'
);

replaceExactly(
    "packages/pyright-scip/package-lock.json",
    '"version": "0.6.6"',
    '"version": "0.6.6-mkso.4"',
    2
);

replaceExactly(
    "packages/pyright-scip/package-lock.json",
    '"diff": "^5.0.0"',
    '"diff": "5.2.2"'
);

replaceExactly(
    "packages/pyright-scip/package-lock.json",
    `"version": "1.1.11",
            "resolved": "https://registry.npmjs.org/brace-expansion/-/brace-expansion-1.1.11.tgz",
            "integrity": "sha512-iCuPHDFgrHX7H2vEI/5xpz07zSHB00TpugqhmYtVmMO6518mCuRMoOYFldEBl0g187ufozdaHgWKcYFb61qGiA=="`,
    `"version": "1.1.18",
            "resolved": "https://registry.npmjs.org/brace-expansion/-/brace-expansion-1.1.18.tgz",
            "integrity": "sha512-Edep/X9fGqVNmzKBVsDYIOtD+z1tuezV70LBjdCst9Tqu76lsnvRiZ6oTic1n+/BIwX6QDGAO94PN4N2SADvtw=="`,
    2
);

replaceExactly(
    "packages/pyright-scip/package-lock.json",
    `"version": "3.1.2",
            "resolved": "https://registry.npmjs.org/minimatch/-/minimatch-3.1.2.tgz",
            "integrity": "sha512-J7p63hRiAjw1NDEww1W7i37+ByIrOWO5XQQAzZ3VOcL0PNybwpfmV/N05zFAzwQ9USyEcX6t3UO+K5aqBQOIHw=="`,
    `"version": "3.1.4",
            "resolved": "https://registry.npmjs.org/minimatch/-/minimatch-3.1.4.tgz",
            "integrity": "sha512-twmL+S8+7yIsE9wsqgzU3E8/LumN3M3QELrBZ20OdmQ9jB2JvW5oZtBEmft84k/Gs5CG9mqtWc6Y9vW+JEzGxw=="`,
    2
);

replaceExactly(
    "packages/pyright-scip/package-lock.json",
    `"version": "5.0.0",
            "resolved": "https://registry.npmjs.org/diff/-/diff-5.0.0.tgz",
            "integrity": "sha512-/VTCrvm5Z0JGty/BWHljh+BAiw3IK+2j87NGMu8Nwc/f48WoDAC395uomO9ZD117ZOBaHmkX1oyLvkVM/aIT3w=="`,
    `"version": "5.2.2",
            "resolved": "https://registry.npmjs.org/diff/-/diff-5.2.2.tgz",
            "integrity": "sha512-vtcDfH3TOjP8UekytvnHH1o1P4FcUdt4eQ1Y+Abap1tk/OB2MWQvcwS2ClCd1zuIhc3JKOx6p3kod8Vfys3E+A=="`,
    2
);

replaceExactly(
    "packages/pyright-scip/package-lock.json",
    `"version": "4.0.2",
            "resolved": "https://registry.npmjs.org/diff/-/diff-4.0.2.tgz",
            "integrity": "sha512-58lmxKSA4BNyLz+HHMUzlOEpg09FV+ev6ZMe3vJihgdxzgcwZ8VoEEPmALCZG9LmqfVoNMMKpttIYTVG6uDY7A=="`,
    `"version": "4.0.4",
            "resolved": "https://registry.npmjs.org/diff/-/diff-4.0.4.tgz",
            "integrity": "sha512-X07nttJQkwkfKfvTPG/KSnE2OMdcUCao6+eXF3wmnIQRn2aPAHH3VxDbDOdegkd6JbPsXqShpvEOHfAT+nCNwQ=="`,
);

replaceExactly(
    "packages/pyright-scip/package-lock.json",
    `"version": "4.0.2",
                    "resolved": "https://registry.npmjs.org/diff/-/diff-4.0.2.tgz",
                    "integrity": "sha512-58lmxKSA4BNyLz+HHMUzlOEpg09FV+ev6ZMe3vJihgdxzgcwZ8VoEEPmALCZG9LmqfVoNMMKpttIYTVG6uDY7A=="`,
    `"version": "4.0.4",
                    "resolved": "https://registry.npmjs.org/diff/-/diff-4.0.4.tgz",
                    "integrity": "sha512-X07nttJQkwkfKfvTPG/KSnE2OMdcUCao6+eXF3wmnIQRn2aPAHH3VxDbDOdegkd6JbPsXqShpvEOHfAT+nCNwQ=="`
);

console.log("Applied mkso scip-python producer emission patch 4");
