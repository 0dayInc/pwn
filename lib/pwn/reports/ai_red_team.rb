# frozen_string_literal: true

require 'json'

module PWN
  module Reports
    # This plugin generates the AI Red Team / LLM Adversarial Analysis
    # results within the root of a given output directory.  Two files are
    # created, a JSON file containing all of the AI RedTeam results and an
    # HTML file which is essentially the UI for the JSON file.
    module AIRedTeam
      # Supported Method Parameters::
      # PWN::Reports::AIRedTeam.generate(
      #   dir_path: 'optional - Directory path to save the report (defaults to .)',
      #   results_hash: 'optional - Hash containing the results of the AI RedTeam analysis (defaults to empty hash structure)',
      #   report_name: 'optional - Name of the report file (defaults to current directory name)'
      # )

      public_class_method def self.generate(opts = {})
        dir_path = opts[:dir_path] ||= '.'
        results_hash = opts[:results_hash] ||= {
          report_name: HTMLEntities.new.encode(report_name.to_s.scrub.strip.chomp),
          data: []
        }

        report_name = opts[:report_name] ||= File.basename(Dir.pwd)
        File.write(
          "#{dir_path}/#{report_name}.json",
          JSON.pretty_generate(results_hash)
        )

        column_names = [
          'Timestamp',
          'Test Case / Security References',
          'Target',
          'Payload# | Payload | Response | AI Analysis | Severity',
          'Raw Content',
          'Test Case'
        ]

        driver_src_uri = 'https://github.com/0dayinc/pwn/blob/master/bin/pwn_ai_red_team'

        html_report = %(#{PWN::Reports::HTMLHeader.generate(column_names: column_names, driver_src_uri: driver_src_uri)}
              $(document).ready(function() {
                var table = $('#pwn_results').DataTable( {
                  "order": [[2, 'asc']],
                  "scrollY": scrollYHeight + "px",
                  "scrollCollapse": true,
                  "searchHighlight": true,
                  "paging": true,
                  "lengthMenu": [25, 50, 100, 250, 500, 1000, 2500, 5000],
                  "drawCallback": function () {
                    var api = this.api();

                    // Redo the row counters
                    api.column(0, {page: 'current'} ).nodes().each(function(cell, i) {
                      cell.innerHTML = i + 1;
                    });

                    // Jump to top of scroll body when utilizing pagination
                    var info = api.page.info();
                    if (info.start !== oldStart) {
                      $('.dt-scroll-body').animate({scrollTop: 0}, 500);
                      oldStart = info.start;
                    }
                  },
                  "ajax": "#{report_name}.json",
                  "deferRender": false,
                  "layout": {
                  },
                  "autoWidth": false,
                  "columns": [
                    { "data": null },
                    {
                      "data": "timestamp",
                      "render": function (data, type, row, meta) {
                        if (type === 'display') {
                          timestamp = htmlEntityEncode(data);
                          return '<table class="squish"><tr><td style="width:70px;" align="left">' + timestamp + '</td></tr></table>';
                        } else {
                          return data;
                        }
                      }
                    },
                    {
                      "data": "security_references",
                      "render": function (data, type, row, meta) {
                        if (type === 'display') {
                          var rt_parts = data['red_team_module'].split('::');
                          var rt_dirname = rt_parts[0].toLowerCase() + '/' + rt_parts[1].toLowerCase() + '/' + rt_parts[2].toLowerCase().replace(/([A-Z])/g, function(x,y){ return '_' + y.toLowerCase(); });
                          var rt_module = rt_parts[3];
                          var rt_test_case = rt_module.replace(/\\.?([A-Z])/g, function (x,y){ if (rt_module.match(/\\.?([A-Z][a-z])/g) ) { return "_" + y.toLowerCase(); } else { return y.toLowerCase(); } }).replace(/^_/g, "");

                          return '<table class="squish"><tr><td style="width:150px;" align="left"><a href="https://github.com/0dayinc/pwn/tree/master/lib/pwn/ai/red_team/' + htmlEntityEncode(rt_test_case) + '.rb" target="_blank">' + htmlEntityEncode(rt_module) + '</a><br /><br /><a href="' + htmlEntityEncode(data['owasp_llm_uri']) + '" target="_blank">OWASP: ' + htmlEntityEncode(data['section'])  + '</a><br /><br /><a href="' + htmlEntityEncode(data['atlas_uri']) + '" target="_blank">MITRE ATLAS: ' + htmlEntityEncode(data['atlas_id'])  + '</a></td></tr></table>';
                        } else {
                          return data['red_team_module'].split("::")[3] + ' | OWASP: ' + data['section'] + ' | ATLAS: ' + data['atlas_id'];
                        }
                      }
                    },
                    {
                      "data": "target",
                      "render": function (data, type, row, meta) {
                        if (type === 'display') {
                          engine = htmlEntityEncode(data['engine']);
                          model = htmlEntityEncode(data['model']);
                          sysrole = htmlEntityEncode(data['system_role_content']);

                          return '<table class="squish"><tr><td style="width:175px;" align="left"><b>Engine:</b> ' + engine + '<br /><b>Model:</b> ' + model + '<br /><b>System:</b> ' + sysrole + '</td></tr></table>';
                        } else {
                          return data['engine'] + ' | ' + data['model'];
                        }
                      }
                    },
                    {
                      "data": "payload_no_and_contents",
                      "render": function (data, type, row, meta) {
                        if (type === 'display') {
                          var pwn_rows = '<table class="multi_line_select squish" style="width: 725px"><tbody>';
                          for (var i = 0; i < data.length; i++) {
                            var tr_class;
                            if (i % 2 == 0) { tr_class = "odd"; } else { tr_class = "even"; }

                            var target_link = row.target;

                            var canned_email_results = 'Timestamp: ' + row.timestamp + '\\n' +
                                                       'Target Engine: ' + $("<div/>").html(target_link['engine']).text() + '\\n' +
                                                       'Target Model: ' + $("<div/>").html(target_link['model']).text() + '\\n\\n' +
                                                       'Attack Payload:\\n\\n' +
                                                       data[i]['payload_no'] + ': ' +
                                                       $("<div/>").html(data[i]['payload'].replace(/\\s{2,}/g, " ")).text() + '\\n\\n' +
                                                       'Target Response:\\n\\n' +
                                                       $("<div/>").html(data[i]['response'].replace(/\\s{2,}/g, " ")).text() + '\\n\\n';

                            var canned_email = 'support@0dayinc.com?subject=Potential%20AI%20Vulnerability%20within%20Target:%20'+ encodeURIComponent(target_link['engine'] + '/' + target_link['model']) +'&body=Greetings,%0A%0AThe%20following%20information%20likely%20represents%20a%20vulnerability%20discovered%20through%20automated%20AI%20red%20team%20testing%20initiatives:%0A%0A' + encodeURIComponent(canned_email_results) + 'Is%20this%20something%20that%20can%20be%20addressed%20immediately%20or%20would%20filing%20a%20bug%20be%20more%20appropriate?%20%20Please%20let%20us%20know%20at%20your%20earliest%20convenience%20to%20ensure%20we%20can%20meet%20security%20expectations%20for%20this%20release.%20%20Thanks%20and%20have%20a%20great%20day!';

                            pwn_rows = pwn_rows.concat('<tr class="' + tr_class + '"><td style="width:40px" align="left">' + htmlEntityEncode(data[i]['payload_no']) + ':&nbsp;</td><td style="width:200px" align="left">' + htmlEntityEncode(data[i]['payload']) + '</td><td style="width:225px" align="left">' + htmlEntityEncode(data[i]['response']) + '</td><td style="width:175px" align="left">' + htmlEntityEncode(data[i]['ai_analysis']) + '</td><td style="width:85px" align="right"><a href="mailto:' + canned_email + '">' + htmlEntityEncode(data[i]['severity']) + '</a></td></tr>');
                          }
                          pwn_rows = pwn_rows.concat('</tbody></table>');
                          return pwn_rows;
                        } else {
                          var lines = [];
                          for (var i = 0; i < data.length; i++) {
                            lines.push(data[i]['payload_no'] + ': ' + data[i]['payload'] + ' | Resp: ' + data[i]['response'] + ' | AI: ' + data[i]['ai_analysis'] + ' | Sev: ' + data[i]['severity']);
                          }
                          return lines.join('\\n');
                        }
                      }
                    },
                    {
                      "data": "raw_content",
                      "render": function (data, type, row, meta) {
                        if (type === 'display') {
                          raw_content = htmlEntityEncode(data);
                          return '<table class="squish"><tr><td style="width:300px;" align="left">' + raw_content + '</td></tr></table>';
                        } else {
                          return data;
                        }
                      }
                    },
                    {
                      "data": "test_case_filter",
                      "render": function (data, type, row, meta) {
                        if (type === 'display') {
                          test_case_filter = htmlEntityEncode(data);
                          return '<table class="squish"><tr><td style="width:300px;" align="left">' + test_case_filter + '</td></tr></table>';
                        } else {
                          return data;
                        }
                      }
                    }
                  ],
                  "initComplete": function(settings, json) {
                    $('#report_name').text(json.report_name);
                    var raw_content_column = 5;
                    var test_case_filter_column = 6;
                    table.column(raw_content_column).visible(false);
                    table.column(test_case_filter_column).visible(false);

                    // Add export buttons after initialization
                    new $.fn.dataTable.Buttons(table, {
                      buttons: [
                        {
                          text: 'Select / Deselect All Lines',
                          action: function () {
                            select_deselect_all();
                          }
                        },
                        {
                          text: 'Export to JSON',
                          action: function () {
                            export_json(table);
                          }
                        },
                        {
                          text: 'Export to XLSX',
                          action: function () {
                            export_xlsx_or_pdf('xlsx');
                          }
                        },
                        {
                          text: 'Export to PDF',
                          action: function () {
                            export_xlsx_or_pdf('pdf');
                          }
                        }
                      ]
                    });

                    table.buttons().container().appendTo('#toggle_col_and_button_group');

                    // Update Smart Search Label with Example
                    $('.dt-search label').text('Smart Search (e.g., "PWNED !refused"):').css({'font-weight': 'bold', color: '#B40404'});
                  }
                });

                function export_xlsx_or_pdf(type) {
                  if ($('.multi_line_select tr.highlighted').length === 0 && !confirm('No lines selected. Export all records?')) {
                    return;
                  }

                  getExportData(table).then(({data, report_name}) => {
                    // Flatten data for export
                    var flatData = [];
                    data.forEach(function(row) {
                      row.payload_no_and_contents.forEach(function(line) {
                        flatData.push({
                          timestamp: row.timestamp,
                          test_case: row.security_references.red_team_module.split('::')[3],
                          owasp_llm: row.security_references.owasp_llm_uri,
                          atlas: row.security_references.atlas_uri,
                          owasp_section: row.security_references.section,
                          atlas_id: row.security_references.atlas_id,
                          engine: row.target.engine,
                          model: row.target.model,
                          payload_no: line.payload_no,
                          payload: line.payload,
                          response: line.response,
                          ai_analysis: line.ai_analysis,
                          severity: line.severity
                        });
                      });
                    });

                    var exportDate = new Date().toLocaleString();
                    var title = '~ pwn ai red team >>> ' + report_name + ' (Exported on ' + exportDate + ')';

                    if (type === 'xlsx') {
                      const workbook = new ExcelJS.Workbook();
                      const worksheet = workbook.addWorksheet('PWN AI RedTeam Results');

                      // Add title row and merge
                      worksheet.mergeCells('A1:K1');
                      const titleCell = worksheet.getCell('A1');
                      titleCell.value = title;
                      titleCell.font = { size: 14, bold: true };
                      titleCell.alignment = { horizontal: 'center' };

                      // Add header row
                      worksheet.addRow(['Timestamp', 'Test Case', 'OWASP LLM', 'MITRE ATLAS', 'Engine', 'Model', 'Payload#', 'Payload', 'Response', 'AI Analysis', 'Severity']);
                      const headerRow = worksheet.getRow(2);
                      headerRow.eachCell((cell) => {
                        cell.font = { bold: true, color: { argb: 'FF000000' } };
                        cell.fill = { type: 'pattern', pattern: 'solid', fgColor: { argb: 'FF999999' } };
                        cell.alignment = { horizontal: 'center', wrapText: true };
                      });

                      // Add data rows with alternating fills and hyperlinks
                      flatData.forEach((item, index) => {
                        const row = worksheet.addRow([
                          item.timestamp,
                          item.test_case,
                          { text: item.owasp_section, hyperlink: item.owasp_llm },
                          { text: item.atlas_id, hyperlink: item.atlas },
                          item.engine,
                          item.model,
                          item.payload_no,
                          item.payload,
                          item.response,
                          item.ai_analysis,
                          item.severity
                        ]);

                        const fill = (index % 2 === 0)
                          ? { type: 'pattern', pattern: 'solid', fgColor: { argb: 'FFDEDEDE' } }
                          : { type: 'pattern', pattern: 'solid', fgColor: { argb: 'FFFFFFFF' } };

                        row.eachCell((cell) => {
                          cell.fill = fill;
                          cell.alignment = { wrapText: true, vertical: 'top', horizontal: 'left' };
                        });
                      });

                      // Set column widths (converted from pixels to character units approx.)
                      const pixelWidthsInches = [1.0, 2.0, 3.0, 1.5, 1.0, 1.5, 0.75, 3.0, 3.5, 3.0, 1.0];
                      worksheet.columns = pixelWidthsInches.map(inches => {
                        let width;
                        width = inches / 0.077
                        return { width: width };
                      });

                      // Freeze header
                      worksheet.views = [{ state: 'frozen', ySplit: 2 }];

                      // Generate and download the file
                      workbook.xlsx.writeBuffer().then(buffer => {
                        const blob = new Blob([buffer], { type: 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet' });
                        const url = URL.createObjectURL(blob);
                        const a = document.createElement('a');
                        a.href = url;
                        a.download = report_name + '.xlsx';
                        a.click();
                        URL.revokeObjectURL(url);
                      });
                    } else if (type === 'pdf') {
                      var docDefinition = {
                        pageOrientation: 'landscape',
                        pageSize: 'LETTER',
                        pageMargins: [10, 10, 10, 10],
                        header: {
                          text: title, margin: [20, 10, 20, 0],
                          fontSize: 12, bold: true,
                          alignment: 'center'
                        },
                        footer: function(currentPage, pageCount) {
                          return {
                            text: 'Page ' + currentPage.toString() + ' of ' + pageCount + ' | Exported on ' + exportDate,
                            alignment: 'center',
                            fontSize: 8,
                            margin: [0, 0, 0, 10]
                          };
                        },
                        content: [
                          {
                            text: title,
                            style: 'header'
                          },
                          {
                            table: {
                              headerRows: 1,
                              widths: [45, 40, 60, 45, 35, 40, 25, 105, 130, 105, 40],
                              body: [
                                ['Timestamp', 'Test Case', 'OWASP LLM', 'MITRE ATLAS', 'Engine', 'Model', 'Payload#', 'Payload', 'Response', 'AI Analysis', 'Severity'],
                                ...flatData.map(r => [
                                  r.timestamp,
                                  r.test_case,
                                  { text: r.owasp_section, link: r.owasp_llm, style: {decoration: 'underline'} },
                                  { text: r.atlas_id, link: r.atlas, style: {decoration: 'underline'} },
                                  r.engine,
                                  r.model,
                                  r.payload_no,
                                  r.payload,
                                  r.response,
                                  r.ai_analysis,
                                  r.severity
                                ])
                              ]
                            },
                            layout: {
                              hLineWidth: function(i, node) { return (i === 0 || i === node.table.body.length) ? 1 : 0.5; },
                              vLineWidth: function(i, node) { return 0.5; },
                              hLineColor: function(i, node) { return '#aaaaaa'; },
                              vLineColor: function(i, node) { return '#aaaaaa'; },
                              fillColor: function (rowIndex, node, columnIndex) {
                                if (rowIndex === 0) {
                                  return '#999999'; // Dark header
                                }
                                return (rowIndex % 2 === 0) ? '#ffffff' : '#dedede'; // White even, gray odd
                              },
                              paddingLeft: function(i, node) { return 4; },
                              paddingRight: function(i, node) { return 4; },
                              paddingTop: function(i, node) { return 2; },
                              paddingBottom: function(i, node) { return 2; }
                            }
                          }
                        ],
                        styles: {
                          header: {
                            fontSize: 12,
                            bold: true,
                            margin: [0, 0, 0, 10]
                          }
                        },
                        defaultStyle: {
                          fontSize: 8,
                          color: '#000000',
                          columnGap: 20
                        }
                      };
                      pdfMake.createPdf(docDefinition).download(report_name + '.pdf');
                    }
                  });
                }
              });
              #{PWN::Reports::HTMLFooter.generate}
        )

        File.open("#{dir_path}/#{report_name}.html", 'w') do |f|
          f.print(html_report)
        end
      rescue StandardError => e
        raise e
        # ensure
        # spin.stop unless spin.nil?
      end

      # Author(s):: 0day Inc. <support@0dayinc.com>

      public_class_method def self.authors
        "AUTHOR(S):
          0day Inc. <support@0dayinc.com>
        "
      end

      # Display Usage for this Module

      public_class_method def self.help
        puts "USAGE:
          #{self}.generate(
            dir_path: dir_path,
            results_hash: results_hash
          )

          #{self}.authors
        "
      end
    end
  end
end
