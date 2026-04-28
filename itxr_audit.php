#!/usr/bin/env php
<?php

declare(strict_types=1);

if (PHP_SAPI !== 'cli') {
    fwrite(STDERR, "This script must be run from the command line.\n");
    exit(1);
}

$options = getopt('', [
    'ips:',
    'xml:',
    'community::',
    'snmp-version::',
    'timeout-ms::',
    'retries::',
    'output-dir::',
    'help::',
]);

if (isset($options['help'])) {
    printUsage();
    exit(0);
}

$ipsFile = $options['ips'] ?? null;
$xmlFile = $options['xml'] ?? null;

if ($ipsFile === null || $xmlFile === null) {
    printUsage();
    exit(1);
}

$community = (string) ($options['community'] ?? 'public');
$snmpVersion = (string) ($options['snmp-version'] ?? '2c');
$timeoutMs = max(1, (int) ($options['timeout-ms'] ?? 1500));
$retries = max(0, (int) ($options['retries'] ?? 1));
$outputDir = (string) ($options['output-dir'] ?? getcwd());

if (!is_file($ipsFile)) {
    fwrite(STDERR, "IPs CSV file not found: {$ipsFile}\n");
    exit(1);
}

if (!is_file($xmlFile)) {
    fwrite(STDERR, "Settings XML file not found: {$xmlFile}\n");
    exit(1);
}

if (!is_dir($outputDir)) {
    fwrite(STDERR, "Output directory does not exist: {$outputDir}\n");
    exit(1);
}

$ips = readIpsFromCsv($ipsFile);
if ($ips === []) {
    fwrite(STDERR, "No valid IP addresses found in: {$ipsFile}\n");
    exit(1);
}

$settings = readSettingsFromXml($xmlFile);
if ($settings === []) {
    fwrite(STDERR, "No ControlXML settings with OIDs found in: {$xmlFile}\n");
    exit(1);
}

fwrite(STDOUT, "Loaded " . count($ips) . " IPs and " . count($settings) . " settings.\n");
fwrite(STDOUT, "Querying SNMP values...\n");

$headers = ['IP'];
foreach ($settings as $setting) {
    $headers[] = $setting['headerName'];
}

$rows = [];
foreach ($ips as $ipIndex => $ip) {
    $row = [$ip];
    foreach ($settings as $setting) {
        [$value, $error] = querySnmpValue(
            $ip,
            $setting['oid'],
            $community,
            $snmpVersion,
            $timeoutMs,
            $retries
        );

        if ($error !== null) {
            $row[] = "ERROR: {$error}";
            continue;
        }

        $row[] = normalizeSnmpValue($value);
    }
    $rows[] = $row;
    fwrite(STDOUT, sprintf("[%d/%d] %s done\n", $ipIndex + 1, count($ips), $ip));
}

$referenceValueByColumn = computeMostCommonValues($rows, count($headers));
$outlierMap = computeOutlierMap($rows, $referenceValueByColumn);

$outputFilename = 'ITXR-AUDIT-' . date('Ymd-His') . '.xlsx';
$outputPath = rtrim($outputDir, DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR . $outputFilename;

writeXlsx($outputPath, $headers, $rows, $outlierMap);

fwrite(STDOUT, "Audit completed: {$outputPath}\n");
exit(0);

function printUsage(): void
{
    $usage = <<<TXT
Usage:
  php itxr_audit.php --ips /path/to/itxr-ips.csv --xml /path/to/ITXR-ALL.xml [options]

Required arguments:
  --ips           CSV file containing ITXR IP addresses
  --xml           XML file containing settings and OIDs (ControlXML elements)

Optional arguments:
  --community     SNMP community string (default: public)
  --snmp-version  SNMP version for command fallback (default: 2c)
  --timeout-ms    SNMP timeout in milliseconds (default: 1500)
  --retries       SNMP retry count (default: 1)
  --output-dir    Directory for output file (default: current directory)
  --help          Show this message

Output:
  Writes ITXR-AUDIT-YYYYmmdd-HHMMSS.xlsx
  - First row contains IP and all setting names
  - For each setting column, values that differ from the most common value are highlighted yellow
  - If all values in a setting column are identical, no cells in that column are highlighted

Notes:
  - Uses PHP SNMP extension (snmp2_get) when available.
  - Falls back to `snmpget` command if the SNMP extension is unavailable.
  - Uses inline XLSX generation; requires ZipArchive extension.

TXT;

    fwrite(STDOUT, $usage);
}

/**
 * @return array<int, string>
 */
function readIpsFromCsv(string $csvFile): array
{
    $handle = fopen($csvFile, 'rb');
    if ($handle === false) {
        throw new RuntimeException("Unable to open IP CSV file: {$csvFile}");
    }

    $ips = [];
    $seen = [];
    while (($fields = fgetcsv($handle)) !== false) {
        if ($fields === [null] || $fields === []) {
            continue;
        }

        $ip = null;
        foreach ($fields as $field) {
            $candidate = trim((string) $field);
            if ($candidate === '') {
                continue;
            }

            if (filter_var($candidate, FILTER_VALIDATE_IP) !== false) {
                $ip = $candidate;
                break;
            }
        }

        if ($ip === null) {
            continue;
        }

        if (!isset($seen[$ip])) {
            $seen[$ip] = true;
            $ips[] = $ip;
        }
    }
    fclose($handle);

    return $ips;
}

/**
 * @return array<int, array{oid: string, name: string, headerName: string}>
 */
function readSettingsFromXml(string $xmlFile): array
{
    libxml_use_internal_errors(true);
    $xml = simplexml_load_file($xmlFile);
    if ($xml === false) {
        $messages = [];
        foreach (libxml_get_errors() as $error) {
            $messages[] = trim($error->message);
        }
        libxml_clear_errors();
        throw new RuntimeException(
            "Unable to parse XML file {$xmlFile}: " . implode('; ', $messages)
        );
    }

    $xml->registerXPathNamespace('c', 'http://castor.exolab.org/');
    $nodes = $xml->xpath('//c:ControlXML');
    if ($nodes === false) {
        throw new RuntimeException("Unable to query ControlXML nodes in XML file: {$xmlFile}");
    }

    $settings = [];
    $headerNameCounts = [];

    foreach ($nodes as $node) {
        $attributes = $node->attributes();
        if ($attributes === null) {
            continue;
        }

        $oid = trim((string) ($attributes['oid'] ?? ''));
        $name = trim((string) ($attributes['name'] ?? ''));

        if ($oid === '' || $name === '') {
            continue;
        }

        $headerName = $name;
        if (isset($headerNameCounts[$headerName])) {
            $headerNameCounts[$headerName]++;
            $headerName = $headerName . ' [' . $oid . ']';
        } else {
            $headerNameCounts[$headerName] = 1;
        }

        $settings[] = [
            'oid' => ltrim($oid, '.'),
            'name' => $name,
            'headerName' => $headerName,
        ];
    }

    return $settings;
}

/**
 * @return array{0: string|null, 1: string|null}
 */
function querySnmpValue(
    string $ip,
    string $oid,
    string $community,
    string $snmpVersion,
    int $timeoutMs,
    int $retries
): array {
    $oidWithDot = ltrim($oid, '.').'.1';

    if (function_exists('snmp2_get')) {
        $lastError = null;
        set_error_handler(static function (int $errno, string $errstr) use (&$lastError): bool {
            $lastError = $errstr;
            return true;
        });

        try {
            $raw = snmp2_get($ip, $community, $oidWithDot, $timeoutMs * 1000, $retries);
        } finally {
            restore_error_handler();
        }

        if ($raw === false) {
            return [null, $lastError !== null ? trim($lastError) : "SNMP query failed for {$oidWithDot}"];
        }

        return [(string) $raw, null];
    }

    $timeoutSeconds = max(1, (int) ceil($timeoutMs / 1000));
    $command = sprintf(
        'snmpget -v %s -c %s -t %d -r %d -Oqv %s %s 2>&1',
        escapeshellarg($snmpVersion),
        escapeshellarg($community),
        $timeoutSeconds,
        $retries,
        escapeshellarg($ip),
        escapeshellarg($oidWithDot)
    );

    $output = [];
    $exitCode = 0;
    exec($command, $output, $exitCode);
    $raw = trim(implode("\n", $output));

    if ($exitCode !== 0) {
        $message = $raw !== '' ? $raw : "snmpget exited with code {$exitCode}";
        return [null, $message];
    }

    if ($raw === '') {
        return [null, "No SNMP value returned for {$oidWithDot}"];
    }

    return [$raw, null];
}

function normalizeSnmpValue(?string $raw): string
{
    if ($raw === null) {
        return '';
    }

    $value = trim($raw);
    $value = preg_replace('/^[A-Z\-]+:\s*/', '', $value) ?? $value;

    if (str_starts_with($value, '"') && str_ends_with($value, '"') && strlen($value) >= 2) {
        $value = substr($value, 1, -1);
    }

    return $value;
}

/**
 * @param array<int, array<int, string>> $rows
 * @return array<int, string|null>
 */
function computeMostCommonValues(array $rows, int $columnCount): array
{
    $mostCommonValues = array_fill(0, $columnCount, null);

    for ($column = 1; $column < $columnCount; $column++) {
        $counts = [];

        foreach ($rows as $row) {
            $value = $row[$column] ?? '';
            if (!isset($counts[$value])) {
                $counts[$value] = 0;
            }
            $counts[$value]++;
        }

        if ($counts === []) {
            continue;
        }

        arsort($counts);
        $mostCommonValue = (string) array_key_first($counts);
        $distinctValueCount = count($counts);

        // If all values are identical in this column, do not highlight anything.
        if ($distinctValueCount === 1) {
            continue;
        }

        $mostCommonValues[$column] = $mostCommonValue;
    }

    return $mostCommonValues;
}

/**
 * @param array<int, array<int, string>> $rows
 * @param array<int, string|null> $referenceValueByColumn
 * @return array<int, array<int, bool>>
 */
function computeOutlierMap(array $rows, array $referenceValueByColumn): array
{
    $outlierMap = [];

    foreach ($rows as $rowIndex => $row) {
        foreach ($referenceValueByColumn as $column => $referenceValue) {
            if ($column === 0 || $referenceValue === null) {
                continue;
            }

            $value = (string) ($row[$column] ?? '');
            if ($value !== (string) $referenceValue) {
                $outlierMap[$rowIndex][$column] = true;
            }
        }
    }

    return $outlierMap;
}

/**
 * @param array<int, string> $headers
 * @param array<int, array<int, string>> $rows
 * @param array<int, array<int, bool>> $outlierMap
 */
function writeXlsx(string $targetPath, array $headers, array $rows, array $outlierMap): void
{
    if (!class_exists('ZipArchive')) {
        throw new RuntimeException('ZipArchive extension is required to write XLSX output.');
    }

    $zip = new ZipArchive();
    if ($zip->open($targetPath, ZipArchive::CREATE | ZipArchive::OVERWRITE) !== true) {
        throw new RuntimeException("Unable to create XLSX file at: {$targetPath}");
    }

    $sheetXml = buildSheetXml($headers, $rows, $outlierMap);

    $zip->addFromString('[Content_Types].xml', buildContentTypesXml());
    $zip->addFromString('_rels/.rels', buildRootRelsXml());
    $zip->addFromString('xl/workbook.xml', buildWorkbookXml());
    $zip->addFromString('xl/_rels/workbook.xml.rels', buildWorkbookRelsXml());
    $zip->addFromString('xl/styles.xml', buildStylesXml());
    $zip->addFromString('xl/worksheets/sheet1.xml', $sheetXml);

    $zip->close();
}

/**
 * @param array<int, string> $headers
 * @param array<int, array<int, string>> $rows
 * @param array<int, array<int, bool>> $outlierMap
 */
function buildSheetXml(array $headers, array $rows, array $outlierMap): string
{
    $totalRows = count($rows) + 1;
    $totalColumns = count($headers);

    $lastCellRef = toExcelColumnName($totalColumns) . $totalRows;

    $xmlRows = [];

    $headerCells = [];
    foreach ($headers as $columnIndex => $header) {
        $ref = toExcelColumnName($columnIndex + 1) . '1';
        $headerCells[] = sprintf(
            '<c r="%s" t="inlineStr" s="1"><is><t>%s</t></is></c>',
            $ref,
            xmlEscape($header)
        );
    }
    $xmlRows[] = '<row r="1">' . implode('', $headerCells) . '</row>';

    foreach ($rows as $rowIndex => $row) {
        $excelRow = $rowIndex + 2;
        $cells = [];

        for ($columnIndex = 0; $columnIndex < $totalColumns; $columnIndex++) {
            $value = (string) ($row[$columnIndex] ?? '');
            $ref = toExcelColumnName($columnIndex + 1) . $excelRow;

            $style = '';
            if (($outlierMap[$rowIndex][$columnIndex] ?? false) === true) {
                $style = ' s="2"';
            }

            $cells[] = sprintf(
                '<c r="%s" t="inlineStr"%s><is><t>%s</t></is></c>',
                $ref,
                $style,
                xmlEscape($value)
            );
        }

        $xmlRows[] = sprintf('<row r="%d">%s</row>', $excelRow, implode('', $cells));
    }

    return '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        . '<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">'
        . '<dimension ref="A1:' . $lastCellRef . '"/>'
        . '<sheetViews><sheetView workbookViewId="0"/></sheetViews>'
        . '<sheetFormatPr defaultRowHeight="15"/>'
        . '<sheetData>' . implode('', $xmlRows) . '</sheetData>'
        . '</worksheet>';
}

function buildContentTypesXml(): string
{
    return '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        . '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
        . '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
        . '<Default Extension="xml" ContentType="application/xml"/>'
        . '<Override PartName="/xl/workbook.xml" '
        . 'ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>'
        . '<Override PartName="/xl/worksheets/sheet1.xml" '
        . 'ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>'
        . '<Override PartName="/xl/styles.xml" '
        . 'ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.styles+xml"/>'
        . '</Types>';
}

function buildRootRelsXml(): string
{
    return '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        . '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
        . '<Relationship Id="rId1" '
        . 'Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" '
        . 'Target="xl/workbook.xml"/>'
        . '</Relationships>';
}

function buildWorkbookXml(): string
{
    return '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        . '<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" '
        . 'xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">'
        . '<sheets>'
        . '<sheet name="ITXR Audit" sheetId="1" r:id="rId1"/>'
        . '</sheets>'
        . '</workbook>';
}

function buildWorkbookRelsXml(): string
{
    return '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        . '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
        . '<Relationship Id="rId1" '
        . 'Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" '
        . 'Target="worksheets/sheet1.xml"/>'
        . '<Relationship Id="rId2" '
        . 'Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" '
        . 'Target="styles.xml"/>'
        . '</Relationships>';
}

function buildStylesXml(): string
{
    return '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        . '<styleSheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">'
        . '<fonts count="2">'
        . '<font><sz val="11"/><name val="Calibri"/></font>'
        . '<font><b/><sz val="11"/><name val="Calibri"/></font>'
        . '</fonts>'
        . '<fills count="3">'
        . '<fill><patternFill patternType="none"/></fill>'
        . '<fill><patternFill patternType="gray125"/></fill>'
        . '<fill><patternFill patternType="solid"><fgColor rgb="FFFFFF00"/><bgColor indexed="64"/></patternFill></fill>'
        . '</fills>'
        . '<borders count="1"><border><left/><right/><top/><bottom/><diagonal/></border></borders>'
        . '<cellStyleXfs count="1"><xf numFmtId="0" fontId="0" fillId="0" borderId="0"/></cellStyleXfs>'
        . '<cellXfs count="3">'
        . '<xf numFmtId="0" fontId="0" fillId="0" borderId="0" xfId="0"/>'
        . '<xf numFmtId="0" fontId="1" fillId="0" borderId="0" xfId="0" applyFont="1"/>'
        . '<xf numFmtId="0" fontId="0" fillId="2" borderId="0" xfId="0" applyFill="1"/>'
        . '</cellXfs>'
        . '<cellStyles count="1"><cellStyle name="Normal" xfId="0" builtinId="0"/></cellStyles>'
        . '</styleSheet>';
}

function xmlEscape(string $value): string
{
    return htmlspecialchars($value, ENT_QUOTES | ENT_XML1);
}

function toExcelColumnName(int $column): string
{
    $name = '';
    while ($column > 0) {
        $mod = ($column - 1) % 26;
        $name = chr(65 + $mod) . $name;
        $column = intdiv($column - 1, 26);
    }

    return $name;
}
