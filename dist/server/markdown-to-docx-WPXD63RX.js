import "./chunk-KFQGP6VL.js";

// server/lib/markdown-to-docx.ts
import * as docx from "docx";
var {
  Document,
  Packer,
  Paragraph,
  TextRun,
  Table,
  TableRow,
  TableCell,
  WidthType,
  AlignmentType,
  HeadingLevel,
  BorderStyle,
  ShadingType,
  PageBreak,
  Header,
  Footer,
  TabStopPosition,
  TabStopType
} = docx;
var severityColor = {
  critical: "FF0000",
  high: "FF6600",
  moderate: "FFAA00",
  medium: "FFAA00",
  low: "3399FF",
  informational: "999999",
  info: "999999"
};
function isHeading(line) {
  const m = line.match(/^(#{1,4})\s+(.+)/);
  if (!m) return null;
  return { level: m[1].length, text: m[2].trim() };
}
function isTableSeparator(line) {
  return /^\|[\s\-:|]+\|$/.test(line.trim());
}
function isTableRow(line) {
  return line.trim().startsWith("|") && line.trim().endsWith("|");
}
function parseTableCells(line) {
  return line.trim().replace(/^\|/, "").replace(/\|$/, "").split("|").map((c) => c.trim());
}
function isBullet(line) {
  const m = line.match(/^(\s*)[-*+]\s+(.+)/);
  if (!m) return null;
  return { indent: Math.floor(m[1].length / 2), text: m[2] };
}
function isNumberedList(line) {
  const m = line.match(/^\s*(\d+)\.\s+(.+)/);
  if (!m) return null;
  return { num: m[1], text: m[2] };
}
function isBlockquote(line) {
  const m = line.match(/^>\s*(.*)/);
  return m ? m[1] : null;
}
function isCodeFence(line) {
  return line.trim().startsWith("```");
}
function isHorizontalRule(line) {
  return /^---+$/.test(line.trim()) || /^\*\*\*+$/.test(line.trim());
}
function parseInline(text) {
  const runs = [];
  const regex = /(\*\*(.+?)\*\*|\*(.+?)\*|`(.+?)`|\[(.+?)\]\((.+?)\))/g;
  let lastIndex = 0;
  let match;
  while ((match = regex.exec(text)) !== null) {
    if (match.index > lastIndex) {
      runs.push(new TextRun({ text: text.slice(lastIndex, match.index), size: 20 }));
    }
    if (match[2]) {
      runs.push(new TextRun({ text: match[2], bold: true, size: 20 }));
    } else if (match[3]) {
      runs.push(new TextRun({ text: match[3], italics: true, size: 20 }));
    } else if (match[4]) {
      runs.push(new TextRun({ text: match[4], font: "Courier New", size: 18, shading: { type: ShadingType.SOLID, color: "F0F0F0" } }));
    } else if (match[5] && match[6]) {
      runs.push(new TextRun({ text: match[5], color: "0066CC", underline: { type: "single" }, size: 20 }));
    }
    lastIndex = match.index + match[0].length;
  }
  if (lastIndex < text.length) {
    runs.push(new TextRun({ text: text.slice(lastIndex), size: 20 }));
  }
  if (runs.length === 0) {
    runs.push(new TextRun({ text, size: 20 }));
  }
  return runs;
}
function buildTable(headerCells, bodyRows) {
  const headerRow = new TableRow({
    tableHeader: true,
    children: headerCells.map(
      (text) => new TableCell({
        shading: { type: ShadingType.SOLID, color: "1a1a2e" },
        children: [
          new Paragraph({
            alignment: AlignmentType.CENTER,
            children: [new TextRun({ text, bold: true, color: "FFFFFF", size: 18 })]
          })
        ]
      })
    )
  });
  const dataRows = bodyRows.map(
    (cells) => new TableRow({
      children: cells.map((cell) => {
        const lower = cell.toLowerCase();
        const color = severityColor[lower];
        return new TableCell({
          children: [
            new Paragraph({
              children: color ? [new TextRun({ text: cell, bold: true, color, size: 18 })] : parseInline(cell).map((r) => {
                return new TextRun({ ...r, size: 18 });
              })
            })
          ]
        });
      })
    })
  );
  return new Table({
    width: { size: 100, type: WidthType.PERCENTAGE },
    rows: [headerRow, ...dataRows]
  });
}
async function markdownToDocx(markdown, opts) {
  const lines = markdown.split("\n");
  const children = [];
  children.push(
    new Paragraph({ spacing: { before: 3e3 }, alignment: AlignmentType.CENTER, children: [] }),
    new Paragraph({
      alignment: AlignmentType.CENTER,
      spacing: { after: 200 },
      children: [new TextRun({ text: opts.title || "Security Assessment Report", bold: true, size: 56, color: "1a1a2e" })]
    }),
    new Paragraph({
      alignment: AlignmentType.CENTER,
      spacing: { after: 100 },
      children: [new TextRun({ text: `${opts.assessmentType.toUpperCase()} REPORT`, size: 28, color: "666666" })]
    }),
    new Paragraph({
      alignment: AlignmentType.CENTER,
      spacing: { after: 400 },
      children: [new TextRun({ text: "CONFIDENTIAL \u2014 For Authorized Personnel Only", size: 22, color: "CC0000", bold: true })]
    }),
    new Paragraph({
      alignment: AlignmentType.CENTER,
      children: [new TextRun({ text: `Prepared for: ${opts.preparedFor}`, size: 22, color: "444444" })]
    }),
    new Paragraph({
      alignment: AlignmentType.CENTER,
      children: [new TextRun({ text: `Prepared by: ${opts.preparedBy}`, size: 22, color: "444444", italics: true })]
    }),
    new Paragraph({
      alignment: AlignmentType.CENTER,
      spacing: { before: 200 },
      children: [new TextRun({ text: `Report Date: ${opts.reportDate}`, size: 20, color: "888888" })]
    }),
    ...opts.reportId ? [
      new Paragraph({
        alignment: AlignmentType.CENTER,
        children: [new TextRun({ text: `Report ID: ${opts.reportId}`, size: 18, color: "888888" })]
      })
    ] : [],
    new Paragraph({ children: [new PageBreak()] })
  );
  let i = 0;
  let inCodeBlock = false;
  let codeLines = [];
  let tableHeader = null;
  let tableBody = [];
  function flushTable() {
    if (tableHeader) {
      children.push(buildTable(tableHeader, tableBody));
      children.push(new Paragraph({ spacing: { after: 100 }, children: [] }));
      tableHeader = null;
      tableBody = [];
    }
  }
  while (i < lines.length) {
    const line = lines[i];
    if (isCodeFence(line)) {
      if (inCodeBlock) {
        flushTable();
        children.push(
          new Paragraph({
            spacing: { before: 100, after: 100 },
            shading: { type: ShadingType.SOLID, color: "2a2a2a" },
            children: codeLines.map(
              (cl, idx) => new TextRun({
                text: cl + (idx < codeLines.length - 1 ? "\n" : ""),
                font: "Courier New",
                size: 16,
                color: "E0E0E0"
              })
            )
          })
        );
        codeLines = [];
        inCodeBlock = false;
      } else {
        flushTable();
        inCodeBlock = true;
      }
      i++;
      continue;
    }
    if (inCodeBlock) {
      codeLines.push(line);
      i++;
      continue;
    }
    if (isTableRow(line)) {
      const cells = parseTableCells(line);
      if (isTableSeparator(line)) {
        i++;
        continue;
      }
      if (!tableHeader) {
        tableHeader = cells;
      } else {
        tableBody.push(cells);
      }
      i++;
      continue;
    } else {
      flushTable();
    }
    if (isHorizontalRule(line)) {
      children.push(
        new Paragraph({
          spacing: { before: 200, after: 200 },
          border: { bottom: { style: BorderStyle.SINGLE, size: 1, color: "CCCCCC" } },
          children: []
        })
      );
      i++;
      continue;
    }
    const heading = isHeading(line);
    if (heading) {
      const headingMap = {
        1: HeadingLevel.HEADING_1,
        2: HeadingLevel.HEADING_1,
        3: HeadingLevel.HEADING_2,
        4: HeadingLevel.HEADING_3
      };
      if (heading.level <= 2 && /^\d+\./.test(heading.text)) {
        children.push(new Paragraph({ children: [new PageBreak()] }));
      }
      children.push(
        new Paragraph({
          heading: headingMap[heading.level] || HeadingLevel.HEADING_3,
          spacing: { before: heading.level <= 2 ? 400 : 200, after: 100 },
          children: [new TextRun({ text: heading.text, bold: true })]
        })
      );
      i++;
      continue;
    }
    const bq = isBlockquote(line);
    if (bq !== null) {
      children.push(
        new Paragraph({
          spacing: { before: 100, after: 100 },
          indent: { left: 720 },
          border: { left: { style: BorderStyle.SINGLE, size: 6, color: "999999" } },
          children: parseInline(bq)
        })
      );
      i++;
      continue;
    }
    const bullet = isBullet(line);
    if (bullet) {
      children.push(
        new Paragraph({
          bullet: { level: Math.min(bullet.indent, 2) },
          children: parseInline(bullet.text)
        })
      );
      i++;
      continue;
    }
    const numbered = isNumberedList(line);
    if (numbered) {
      children.push(
        new Paragraph({
          spacing: { after: 60 },
          children: [
            new TextRun({ text: `${numbered.num}. `, bold: true, size: 20 }),
            ...parseInline(numbered.text)
          ]
        })
      );
      i++;
      continue;
    }
    if (line.trim() === "") {
      i++;
      continue;
    }
    children.push(
      new Paragraph({
        spacing: { after: 120 },
        children: parseInline(line)
      })
    );
    i++;
  }
  flushTable();
  const doc = new Document({
    creator: opts.preparedBy || "Ace of Cloud LLC",
    title: opts.title || "Security Assessment Report",
    description: `${opts.assessmentType} Report`,
    styles: {
      default: {
        document: {
          run: { font: "Calibri", size: 20 }
        },
        heading1: {
          run: { font: "Calibri", size: 32, bold: true, color: "1a1a2e" },
          paragraph: { spacing: { before: 360, after: 120 } }
        },
        heading2: {
          run: { font: "Calibri", size: 26, bold: true, color: "333333" },
          paragraph: { spacing: { before: 240, after: 100 } }
        },
        heading3: {
          run: { font: "Calibri", size: 22, bold: true, color: "444444" },
          paragraph: { spacing: { before: 200, after: 80 } }
        }
      }
    },
    sections: [
      {
        properties: {
          page: {
            margin: { top: 1440, right: 1440, bottom: 1440, left: 1440 }
          }
        },
        headers: {
          default: new Header({
            children: [
              new Paragraph({
                alignment: AlignmentType.CENTER,
                children: [
                  new TextRun({
                    text: "CONFIDENTIAL \u2014 Security Assessment Report",
                    size: 16,
                    color: "999999",
                    italics: true
                  })
                ]
              })
            ]
          })
        },
        footers: {
          default: new Footer({
            children: [
              new Paragraph({
                alignment: AlignmentType.CENTER,
                children: [
                  new TextRun({
                    text: `${opts.preparedBy || "Ace of Cloud LLC"} \u2014 ${opts.reportDate}`,
                    size: 16,
                    color: "999999"
                  })
                ]
              })
            ]
          })
        },
        children
      }
    ]
  });
  const buffer = await Packer.toBuffer(doc);
  return Buffer.from(buffer);
}
export {
  markdownToDocx
};
