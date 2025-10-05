# frozen_string_literal: true

require 'json'
require 'tty-spinner'

module PWN
  module Reports
    # This plugin generates the Static Code Anti-Pattern Matching Analysis
    # results within the root of a given source repo.  Two files are created,
    # a JSON file containing all of the SAST results and an HTML file
    # which is essentially the UI for the JSON file.
    module SAST
      # Supported Method Parameters::
      # PWN::Reports::SAST.generate(
      #   dir_path: 'optional - Directory path to save the report (defaults to .)',
      #   results_hash: 'optional - Hash containing the results of the SAST analysis (defaults to empty hash structure)',
      #   report_name: 'optional - Name of the report file (defaults to current directory name)'
      # )

      public_class_method def self.generate(opts = {})
        dir_path = opts[:dir_path] ||= '.'
        results_hash = opts[:results_hash] ||= {
          report_name: HTMLEntities.new.encode(report_name.to_s.scrub.strip.chomp),
          data: []
        }
        report_name = opts[:report_name] ||= File.basename(Dir.pwd)

        # Calculate percentage of AI analysis based on the number of entries
        # total_entries = results_hash[:data].sum { |entry| entry[:line_no_and_contents].size }
        # puts "Total entries to analyze: #{total_entries}" if engine

        # percent_complete = 0.0
        # entry_count = 0
        # spin = TTY::Spinner.new(
        #   '[:spinner] Report Generation Progress: :percent_complete :entry_count of :total_entries',
        #   format: :dots,
        #   hide_cursor: true
        # )
        # spin.auto_spin

        # ai_instrospection = PWN::Env[:ai][:introspection]
        # puts "Analyzing source code using AI engine: #{engine}\nModel: #{model}\nSystem Role Content: #{system_role_content}\nTemperature: #{temp}" if ai_instrospection

        # results_hash[:data].each do |hash_line|
        #   git_repo_root_uri = hash_line[:filename][:git_repo_root_uri]
        #   filename = hash_line[:filename][:entry]
        #   hash_line[:line_no_and_contents].each do |src_detail|
        #     entry_count += 1
        #     percent_complete = (entry_count.to_f / total_entries * 100).round(2)
        #     line_no = src_detail[:line_no]
        #     source_code_snippet = src_detail[:contents]
        #     author = src_detail[:author].to_s.scrub.chomp.strip
        #     response = nil
        #     if ai_instrospection
        #       request = {
        #         scm_uri: "#{git_repo_root_uri}/#{filename}",
        #         line: line_no,
        #         source_code_snippet: source_code_snippet
        #       }.to_json
        #       response = PWN::AI::Introspection.reflect(request: request)
        #     end
        #     ai_analysis = nil
        #     if response.is_a?(Hash)
        #       ai_analysis = response[:choices].last[:text] if response[:choices].last.keys.include?(:text)
        #       ai_analysis = response[:choices].last[:content] if response[:choices].last.keys.include?(:content)
        #       puts "AI Analysis Progress: #{percent_complete}% Line: #{line_no} | Author: #{author} | AI Analysis: #{ai_analysis}\n\n\n" if ai_analysis
        #     end
        #     src_detail[:ai_analysis] = ai_analysis.to_s.scrub.chomp.strip
        #    spin.update(
        #      percent_complete: "#{percent_complete}%",
        #      entry_count: entry_count,
        #      total_entries: total_entries
        #    )
        #  end
        # end

        # JSON object Completion
        # File.open("#{dir_path}/pwn_scan_git_source.json", 'w') do |f|
        #   f.print(results_hash.to_json)
        # end
        File.write(
          "#{dir_path}/#{report_name}.json",
          JSON.pretty_generate(results_hash)
        )

        column_names = [
          'Timestamp',
          'Test Case / Security References',
          'Path',
          'Line# | Source | AI Analysis | Author',
          'Raw Content',
          'Test Case'
        ]

        driver_src_uri = 'https://github.com/0dayinc/pwn/blob/master/bin/pwn_sast'

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
                          var sast_dirname = data['sast_module'].split('::')[0].toLowerCase() + '/' + data['sast_module'].split('::')[1].toLowerCase();
                          var sast_module = data['sast_module'].split('::')[2];
                          var sast_test_case = sast_module.replace(/\\.?([A-Z])/g, function (x,y){ if (sast_module.match(/\\.?([A-Z][a-z])/g) ) { return "_" + y.toLowerCase(); } else { return y.toLowerCase(); } }).replace(/^_/g, "");

                          return '<table class="squish"><tr><td style="width:125px;" align="left"><a href="https://github.com/0dayinc/pwn/tree/master/lib/' + htmlEntityEncode(sast_dirname) + '/' + htmlEntityEncode(sast_test_case) + '.rb" target="_blank">' + htmlEntityEncode(data['sast_module'].split("::")[2]) + '</a><br /><br /><a href="' + htmlEntityEncode(data['nist_800_53_uri']) + '" target="_blank">NIST 800-53: ' + htmlEntityEncode(data['section'])  + '</a><br /><br /><a href="' + htmlEntityEncode(data['cwe_uri']) + '" target="_blank">CWE:' + htmlEntityEncode(data['cwe_id'])  + '</a></td></tr></table>';
                        } else {
                          return data['sast_module'].split("::")[2] + ' | NIST 800-53: ' + data['section'] + ' | CWE:' + data['cwe_id'];
                        }
                      }
                    },
                    {
                      "data": "filename",
                      "render": function (data, type, row, meta) {
                        if (type === 'display') {
                          line_entry_uri = htmlEntityEncode(
                            data['git_repo_root_uri'] + '/' + data['entry']
                          );

                          file = htmlEntityEncode(data['entry']);

                          return '<table class="squish"><tr><td style="width:200px;" align="left"><a href="' + line_entry_uri + '" target="_blank">' + file + '</a></td></tr></table>';
                        } else {
                          return data['entry'];
                        }
                      }
                    },
                    {
                      "data": "line_no_and_contents",
                      "render": function (data, type, row, meta) {
                        if (type === 'display') {
                          var pwn_rows = '<table class="multi_line_select squish" style="width: 725px"><tbody>';
                          for (var i = 0; i < data.length; i++) {
                            var tr_class;
                            if (i % 2 == 0) { tr_class = "odd"; } else { tr_class = "even"; }

                            var filename_link = row.filename;

                            var author_and_email_arr = data[i]['author'].split(" ");
                            var email = author_and_email_arr[author_and_email_arr.length - 1];
                            var email_user_arr = email.split("@");
                            var assigned_to = email_user_arr[0].replace("&lt;", "");

                            var uri = '#uri';

                            var canned_email_results = 'Timestamp: ' + row.timestamp + '\\n' +
                                                       'Source Code File Impacted: ' + $("<div/>").html(filename_link).text() + '\\n\\n' +
                                                       'Source Code in Question:\\n\\n' +
                                                       data[i]['line_no'] + ': ' +
                                                       $("<div/>").html(data[i]['contents'].replace(/\\s{2,}/g, " ")).text() + '\\n\\n';

                            var canned_email = email.replace("&lt;", "").replace("&gt;", "") + '?subject=Potential%20Bug%20within%20Source%20File:%20'+ encodeURIComponent(row.filename) +'&body=Greetings,%0A%0AThe%20following%20information%20likely%20represents%20a%20bug%20discovered%20through%20automated%20security%20testing%20initiatives:%0A%0A' + encodeURIComponent(canned_email_results) + 'Is%20this%20something%20that%20can%20be%20addressed%20immediately%20or%20would%20filing%20a%20bug%20be%20more%20appropriate?%20%20Please%20let%20us%20know%20at%20your%20earliest%20convenience%20to%20ensure%20we%20can%20meet%20security%20expectations%20for%20this%20release.%20%20Thanks%20and%20have%20a%20great%20day!';

                            domain = line_entry_uri.replace('http://','').replace('https://','').split(/[/?#]/)[0];
                            if (domain.includes('stash') || domain.includes('bitbucket') || domain.includes('gerrit')) {
                              to_line_number = line_entry_uri + '#' + data[i]['line_no'];
                            } else {
                              // e.g. GitHub, GitLab, etc.
                              to_line_number = line_entry_uri + '#L' + data[i]['line_no'];
                            }

                            pwn_rows = pwn_rows.concat('<tr class="' + tr_class + '"><td style="width:50px" align="left"><a href="' + htmlEntityEncode(to_line_number) + '" target="_blank">' + htmlEntityEncode(data[i]['line_no']) + '</a>:&nbsp;</td><td style="width:300px" align="left">' + htmlEntityEncode(data[i]['contents']) + '</td><td style="width:200px" align=:left">' + htmlEntityEncode(data[i]['ai_analysis']) + '</td><td style="width:175px" align="right"><a href="mailto:' + canned_email + '">' + htmlEntityEncode(data[i]['author']) + '</a></td></tr>');
                          }
                          pwn_rows = pwn_rows.concat('</tbody></table>');
                          return pwn_rows;
                        } else {
                          var lines = [];
                          for (var i = 0; i < data.length; i++) {
                            lines.push(data[i]['line_no'] + ': ' + data[i]['contents'] + ' | AI: ' + data[i]['ai_analysis'] + ' | By: ' + data[i]['author']);
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
                    $('.dt-search label').text('Smart Search (e.g., "password !secure"):').css({'font-weight': 'bold', color: '#B40404'});
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
                      row.line_no_and_contents.forEach(function(line) {
                        flatData.push({
                          timestamp: row.timestamp,
                          test_case: row.security_references.sast_module.split('::')[2],
                          nist_800_53_security_control: row.security_references.nist_800_53_uri,
                          cwe: row.security_references.cwe_uri,
                          nist_section: row.security_references.section,
                          cwe_id: row.security_references.cwe_id,
                          path: row.filename.entry,
                          line_no: line.line_no,
                          contents: line.contents,
                          ai_analysis: line.ai_analysis,
                          author: line.author
                        });
                      });
                    });

                    var exportDate = new Date().toLocaleString();
                    var title = '~ pwn sast >>> ' + report_name + ' (Exported on ' + exportDate + ')';

                    if (type === 'xlsx') {
                      const workbook = new ExcelJS.Workbook();
                      const worksheet = workbook.addWorksheet('PWN SAST Results');

                      // Add title row and merge
                      worksheet.mergeCells('A1:I1');
                      const titleCell = worksheet.getCell('A1');
                      titleCell.value = title;
                      titleCell.font = { size: 14, bold: true };
                      titleCell.alignment = { horizontal: 'center' };

                      // Add header row
                      worksheet.addRow(['Timestamp', 'Test Case', 'NIST 800-53', 'CWE', 'Path', 'Line#', 'Content', 'AI Analysis', 'Author']);
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
                          { text: item.nist_section, hyperlink: item.nist_800_53_security_control },
                          { text: item.cwe_id, hyperlink: item.cwe },
                          item.path,
                          item.line_no,
                          item.contents,
                          item.ai_analysis,
                          item.author
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
                      const pixelWidthsInches = [1.0, 2.0, 4.5, 0.5, 2.5, 0.75, 3.5, 3.5, 2];
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
                              widths: [45, 40, 70, 30, 80, 30, 165, 165, 70],
                              body: [
                                ['Timestamp', 'Test Case', 'NIST 800-53', 'CWE', 'Path', 'Line#', 'Content', 'AI Analysis', 'Author'],
                                ...flatData.map(r => [
                                  r.timestamp,
                                  r.test_case,
                                  { text: r.nist_section, link: r.nist_800_53_security_control, style: {decoration: 'underline'} },
                                  { text: r.cwe_id, link: r.cwe, style: {decoration: 'underline'} },
                                  r.path,
                                  r.line_no,
                                  r.contents,
                                  r.ai_analysis,
                                  r.author
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
