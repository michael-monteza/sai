<?php
declare(strict_types=1);

namespace Saip;

/** Minimal single-sheet .xlsx writer (stored zip, inline strings). No zip extension required. Cells are never formulas. zip() is also used for the collector package. */
final class Xlsx
{
    /** @param list<string> $header @param list<list<mixed>> $rows */
    public static function build(string $sheet, array $header, array $rows): string
    {
        $col = static function (int $i): string { $s = ''; for ($i++; $i > 0; $i = intdiv($i - 1, 26)) $s = chr(65 + ($i - 1) % 26) . $s; return $s; };
        $cell = static function (int $c, int $r, mixed $v) use ($col): string {
            $ref = $col($c) . $r;
            if (is_int($v) || is_float($v)) return "<c r=\"$ref\"><v>$v</v></c>";
            if (is_string($v) && preg_match('/^-?\d{1,15}(\.\d+)?$/', $v) && !preg_match('/^0\d/', $v)) return "<c r=\"$ref\"><v>$v</v></c>";
            if ($v === null || $v === '') return '';
            $x = htmlspecialchars(preg_replace('/[\x00-\x08\x0B\x0C\x0E-\x1F]/', '', (string)$v), ENT_XML1 | ENT_QUOTES, 'UTF-8');
            return "<c r=\"$ref\" t=\"inlineStr\"><is><t xml:space=\"preserve\">$x</t></is></c>";
        };
        $xml = '<?xml version="1.0" encoding="UTF-8" standalone="yes"?><worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><sheetData>';
        $r = 1;
        foreach ([$header, ...$rows] as $row) {
            $xml .= "<row r=\"$r\">";
            foreach (array_values($row) as $c => $v) $xml .= $cell($c, $r, $v);
            $xml .= '</row>'; $r++;
        }
        $xml .= '</sheetData></worksheet>';
        $name = htmlspecialchars(mb_substr(preg_replace('/[\\\\\/?*\[\]:]/', ' ', $sheet), 0, 31), ENT_XML1 | ENT_QUOTES, 'UTF-8');
        return self::zip([
            '[Content_Types].xml' => '<?xml version="1.0" encoding="UTF-8"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/><Override PartName="/xl/worksheets/sheet1.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/></Types>',
            '_rels/.rels' => '<?xml version="1.0" encoding="UTF-8"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/></Relationships>',
            'xl/workbook.xml' => '<?xml version="1.0" encoding="UTF-8"?><workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"><sheets><sheet name="' . $name . '" sheetId="1" r:id="rId1"/></sheets></workbook>',
            'xl/_rels/workbook.xml.rels' => '<?xml version="1.0" encoding="UTF-8"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet1.xml"/></Relationships>',
            'xl/worksheets/sheet1.xml' => $xml,
        ]);
    }

    /** @param array<string,string> $files */
    public static function zip(array $files): string
    {
        $out = ''; $dir = ''; $n = 0;
        foreach ($files as $name => $data) {
            $crc = crc32($data); $len = strlen($data); $off = strlen($out);
            $out .= pack('VvvvvvVVVvv', 0x04034b50, 20, 0, 0, 0, 0x21, $crc, $len, $len, strlen($name), 0) . $name . $data;
            $dir .= pack('VvvvvvvVVVvvvvvVV', 0x02014b50, 20, 20, 0, 0, 0, 0x21, $crc, $len, $len, strlen($name), 0, 0, 0, 0, 0, $off) . $name;
            $n++;
        }
        return $out . $dir . pack('VvvvvVVv', 0x06054b50, 0, 0, $n, $n, strlen($dir), strlen($out), 0);
    }
}
