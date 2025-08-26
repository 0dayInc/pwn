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
      #   report_name: 'optional - Name of the report file (defaults to current directory name)',
      #   ai_engine: 'optional - AI engine to use for analysis (:grok, :ollama, or :openai)',
      #   ai_model: 'optionnal - AI Model to Use for Respective AI Engine (e.g., grok-4i-0709, chargpt-4o-latest, llama-3.1, etc.)',
      #   ai_key: 'optional -  AI Key/Token for Respective AI Engine',
      #   ai_fqdn: 'optional -  AI FQDN (Only Required for "ollama" AI Engine)',
      #   ai_system_role_content: 'optional - AI System Role Content (Defaults to "Is this code vulnerable or a false positive?  Valid responses are only: "VULNERABLE" or "FALSE+". DO NOT PROVIDE ANY OTHER TEXT OR EXPLANATIONS.")',
      #   ai_temp: 'optional - AI Temperature (Defaults to 0.9)'
      # )

      public_class_method def self.generate(opts = {})
        dir_path = opts[:dir_path] ||= '.'
        results_hash = opts[:results_hash] ||= {
          report_name: HTMLEntities.new.encode(report_name.to_s.scrub.strip.chomp),
          data: []
        }
        report_name = opts[:report_name] ||= File.basename(Dir.pwd)

        ai_engine = opts[:ai_engine]
        if ai_engine
          ai_engine = ai_engine.to_s.to_sym
          valid_ai_engines = %i[grok ollama openai]
          raise "ERROR: Invalid AI Engine. Valid options are: #{valid_ai_engines.join(', ')}" unless valid_ai_engines.include?(ai_engine)

          ai_fqdn = opts[:ai_fqdn]
          raise 'ERROR: FQDN for Ollama AI engine is required.' if ai_engine == :ollama && ai_fqdn.nil?

          ai_model = opts[:ai_model]
          raise 'ERROR: AI Model is required for AI engine ollama.' if ai_engine == :ollama && ai_model.nil?

          ai_key = opts[:ai_key] ||= PWN::Plugins::AuthenticationHelper.mask_password(prompt: "#{ai_engine} Token")
          ai_system_role_content = opts[:ai_system_role_content] ||= 'Is this code vulnerable or a false positive?  Valid responses are only: "VULNERABLE" or "FALSE+". If this code is VULNERABLE, why?'
          ai_temp = opts[:ai_temp] ||= 0.9

          puts "Analyzing source code using AI engine: #{ai_engine}\nModel: #{ai_model}\nSystem Role Content: #{ai_system_role_content}\nTemperature: #{ai_temp}"
        end

        # Calculate percentage of AI analysis based on the number of entries
        total_entries = results_hash[:data].sum { |entry| entry[:line_no_and_contents].size }
        puts "Total entries to analyze: #{total_entries}" if ai_engine

        percent_complete = 0.0
        entry_count = 0
        spin = TTY::Spinner.new(
          '[:spinner] Report Generation Progress: :percent_complete :entry_count of :total_entries',
          format: :dots,
          hide_cursor: true
        )
        spin.auto_spin

        results_hash[:data].each do |hash_line|
          hash_line[:line_no_and_contents].each do |src_detail|
            entry_count += 1
            percent_complete = (entry_count.to_f / total_entries * 100).round(2)
            request = src_detail[:contents]
            response = nil
            line_no = src_detail[:line_no]
            author = src_detail[:author].to_s.scrub.chomp.strip

            case ai_engine
            when :grok
              response = PWN::AI::Grok.chat(
                token: ai_key,
                model: ai_model,
                system_role_content: ai_system_role_content,
                temp: ai_temp,
                request: request.chomp,
                spinner: false
              )
            when :ollama
              response = PWN::AI::Ollama.chat(
                fqdn: ai_fqdn,
                token: ai_key,
                model: ai_model,
                system_role_content: ai_system_role_content,
                temp: ai_temp,
                request: request.chomp,
                spinner: false
              )
            when :openai
              response = PWN::AI::OpenAI.chat(
                token: ai_key,
                model: ai_model,
                system_role_content: ai_system_role_content,
                temp: ai_temp,
                request: request.chomp,
                spinner: false
              )
            end

            ai_analysis = nil
            if response.is_a?(Hash)
              ai_analysis = response[:choices].last[:text] if response[:choices].last.keys.include?(:text)
              ai_analysis = response[:choices].last[:content] if response[:choices].last.keys.include?(:content)
              # puts "AI Analysis Progress: #{percent_complete}% Line: #{line_no} | Author: #{author} | AI Analysis: #{ai_analysis}\n\n\n" if ai_analysis
            end
            src_detail[:ai_analysis] = ai_analysis.to_s.scrub.chomp.strip

            spin.update(
              percent_complete: "#{percent_complete}%",
              entry_count: entry_count,
              total_entries: total_entries
            )
          end
        end
        # JSON object Completion
        # File.open("#{dir_path}/pwn_scan_git_source.json", 'w') do |f|
        #   f.print(results_hash.to_json)
        # end
        File.write(
          "#{dir_path}/#{report_name}.json",
          JSON.pretty_generate(results_hash)
        )

        html_report = %{<!DOCTYPE HTML>
        <html>
          <head>
            <!-- favicon.ico from https://0dayinc.com -->
            <link rel="icon" href="data:image/x-icon;base64,AAABAAEAEBAAAAEAIABoBAAAFgAAACgAAAAQAAAAIAAAAAEAIAAAAAAAAAQAABIXAAASFwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAIkAAACJAgAAiSYAAIlbAACJcAAAiX0AAIlmAACJLQAAiQQAAIkAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAIkAAACJAAAAiS0AAIluAACJdwAAiXgAAIl+AACJeAAAiXQAAIk5AACJAQAAiQAAAAAAAAAAAAAAAAAAAAAAAACJAAAAiRgAAIlvAACJbQAAiXcAAIl7AACJcwAAiXEAAIl1AACJZwAAiR4AAIkAAACJAAAAAAAAAAAAAACJAAAAiQAAAIlEAACJfAAAiXIAAIlyAACJewAAiX4AAIl5AACJdQAAiXcAAIlIAACJAAAAiQAAAAAAAAAAAAAAiQAAAIkJAACJWQAAiXUAAIl9AACJdAAAiYYAAImLAACJdAAAiXkAAImNAACJfQAAiQwAAIkAAAAAAAAAAAAAAIkAAACJFQAAiWsAAIl2AACJfAAAiYIAAImCAACJfwAAiXYAAIl5AACJiQAAiYYAAIkWAACJAAAAAAAAAAAAAACJAAAAiSAAAIl2AACJeQAAiXkAAIl1AACJfwAAiYEAAIl8AACJbwAAiXoAAImBAACJFgAAiQAAAAAAAAAAAAAAiQAAAIkpAACJeAAAiXMAAIl3AACJeQAAiXUAAImAAACJfwAAiWYAAIl4AACJfwAAiR4AAIkAAAAAAAAAAAAAAIkAAACJKAAAiXkAAIlyAACJdQAAiXQAAIluAACJfAAAiXwAAIl3AACJewAAiXwAAIkvAACJAAAAAAAAAAAAAACJAAAAiSMAAIl4AACJdgAAiXsAAIl1AACJcQAAiXcAAIl6AACJeQAAiXoAAIl0AACJKQAAiQAAAAAAAAAAAAAAiQAAAIkXAACJaAAAiXgAAIl3AACJfAAAiXkAAIl3AACJZwAAiXcAAIl0AACJagAAiSgAAIkAAAAAAAAAAAAAAIkAAACJDgAAiV4AAIl5AACJbwAAiW4AAIl9AACJewAAiXcAAIl6AACJfQAAiW8AAIkWAACJAAAAAAAAAAAAAACJAAAAiQ0AAIllAACJewAAiXYAAIl4AACJdQAAiXUAAIl4AACJbQAAiXkAAIlNAACJAwAAiQAAAAAAAAAAAAAAiQAAAIkCAACJPQAAiXMAAIl2AACJeAAAiWgAAIlsAACJfQAAiXsAAIlwAACJGQAAiQAAAIkAAAAAAAAAAAAAAAAAAACJAAAAiQcAAIk4AACJXAAAiXoAAIl7AACJfAAAiYAAAIlsAACJJwAAiQMAAIkAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAIkAAACJAQAAiSsAAIluAACJewAAiXwAAIluAACJKgAAiQAAAIkAAAAAAAAAAAAAAAAA8A8AAPAHAADgBwAA4AcAAMADAADAAwAAwAMAAMADAADAAwAAwAMAAMADAADAAwAAwAMAAMAHAADgBwAA8B8AAA==" type="image/x-icon" />
            <style>
              body {
                font-family: Verdana, Geneva, sans-serif;
                font-size: 11px;
                background-color: #FFFFFF;
                color: #084B8A !important;
              }

              a:link {
                color: #0174DF;
                text-decoration: none;
              }

              a:visited {
                color: #B40404;
                text-decoration: none;
              }

              a:hover {
                color: #01A9DB;
                text-decoration: underline;
              }

              a:active {
                color: #610B5E;
                text-decoration: underline;
              }

              div.dt-container {
                width: 1275px !important;
              }

              div.dt-scroll-body {
                width: 1275px !important;
              }

              table {
                width: 100%;
                border-spacing:0px;
              }

              table.squish {
                table-layout: fixed;
              }

              td {
                vertical-align: top;
                word-wrap: break-word !important;
                border: none !important;
              }

              table.multi_line_select tr.odd {
                background-color: #dedede !important;  /* Gray for odd rows */
              }

              table.multi_line_select tr.even {
                background-color: #ffffff !important;  /* White for even rows */
              }

              tr.highlighted td {
                background-color: #FFF396 !important;
              }
            </style>

            <!-- jQuery & DataTables -->
            <script type="text/javascript" src="https://code.jquery.com/jquery-3.7.1.min.js"></script>

            <link href="https://cdn.datatables.net/v/dt/jszip-3.10.1/dt-2.3.3/b-3.2.4/b-colvis-3.2.4/b-html5-3.2.4/b-print-3.2.4/fc-5.0.4/fh-4.0.3/kt-2.12.1/r-3.0.6/rg-1.5.2/rr-1.5.0/sc-2.4.3/sb-1.8.3/sp-2.3.5/sl-3.1.0/datatables.min.css" rel="stylesheet" integrity="sha384-51NLFpi/9qR2x0LAjQHiFAjV765f0g9+05EmKQ/QWINR/y3qonty8mPy68vEbo0z" crossorigin="anonymous">

            <script src="https://cdnjs.cloudflare.com/ajax/libs/pdfmake/0.2.7/pdfmake.min.js" integrity="sha384-VFQrHzqBh5qiJIU0uGU5CIW3+OWpdGGJM9LBnGbuIH2mkICcFZ7lPd/AAtI7SNf7" crossorigin="anonymous"></script>

            <script src="https://cdnjs.cloudflare.com/ajax/libs/pdfmake/0.2.7/vfs_fonts.js" integrity="sha384-/RlQG9uf0M2vcTw3CX7fbqgbj/h8wKxw7C3zu9/GxcBPRKOEcESxaxufwRXqzq6n" crossorigin="anonymous"></script>

            <script src="https://cdn.datatables.net/v/dt/jszip-3.10.1/dt-2.3.3/b-3.2.4/b-colvis-3.2.4/b-html5-3.2.4/b-print-3.2.4/fc-5.0.4/fh-4.0.3/kt-2.12.1/r-3.0.6/rg-1.5.2/rr-1.5.0/sc-2.4.3/sb-1.8.3/sp-2.3.5/sl-3.1.0/datatables.min.js" integrity="sha384-jvnxkXTB++rTO/pbg6w5nj0jm5HiSGtTcBW5vnoLGRfmSxw3eyqNA0bJ+m6Skjw/" crossorigin="anonymous"></script>

            <script src="https://cdn.sheetjs.com/xlsx-0.20.2/package/dist/xlsx.full.min.js"></script>

            <!--
            <script type="text/javascript" src="//code.jquery.com/jquery-3.6.0.min.js"></script>

            <link rel="stylesheet" type="text/css" href="//cdn.datatables.net/v/dt/dt-1.11.4/b-2.2.2/b-colvis-2.2.2/b-html5-2.2.2/b-print-2.2.2/cr-1.5.5/fc-4.0.1/fh-3.2.1/kt-2.6.4/r-2.2.9/rg-1.1.4/rr-1.2.8/sc-2.0.5/sp-1.4.0/sl-1.3.4/datatables.min.css"/>

            <script type="text/javascript" src="//cdn.datatables.net/v/dt/dt-1.11.4/b-2.2.2/b-colvis-2.2.2/b-html5-2.2.2/b-print-2.2.2/cr-1.5.5/fc-4.0.1/fh-3.2.1/kt-2.6.4/r-2.2.9/rg-1.1.4/rr-1.2.8/sc-2.0.5/sp-1.4.0/sl-1.3.4/datatables.min.js"></script>
            -->
          </head>

          <body id="pwn_body">

            <h1 style="display:inline">
              <a href="https://github.com/0dayinc/pwn/tree/master">~ pwn sast</a>
            </h1><br /><br />
            <h2 id="report_name"></h2><br />

            <div class="dt-buttons" id="button_group">
              <!--<button type="button" id="debug_rows_selected">Rows Selected</button>-->
            </div>

            <div>
              <b>Toggle Column(s) Visibility:</b>&nbsp;
              <a class="toggle-vis" data-column="1" href="#">Timestamp</a>&nbsp;|&nbsp;
              <a class="toggle-vis" data-column="2" href="#">Test Case / Security References</a>&nbsp;|&nbsp;
              <a class="toggle-vis" data-column="3" href="#">Path</a>&nbsp;|&nbsp;
              <a class="toggle-vis" data-column="4" href="#">Line#, Formatted Content, AI Analysis, &amp; Last Committed By</a>&nbsp;|&nbsp;
              <a class="toggle-vis" data-column="5" href="#">Raw Content</a>&nbsp;|&nbsp;
              <a class="toggle-vis" data-column="6" href="#">Test Case (Anti-Pattern) Filter</a>
            </div>
            <br /><br />

            <div>
              Search tips: Use space-separated keywords for AND search, prefix with - to exclude (e.g., "security -password"), or enclose in / / for regex (e.g., "/^important.*$/i").
            </div><br />

            <div>
              <table id="pwn_scan_git_source_results" class="display" cellspacing="0">
                <thead>
                  <tr>
                    <th>#</th>
                    <th>Timestamp</th>
                    <th>Test Case / Security References</th>
                    <th>Path</th>
                    <th>Line#, Formatted Content, AI Analysis, &amp; Last Committed By</th>
                    <th>Raw Content</th>
                    <th>Test Case (Anti-Pattern) Filter</th>
                  </tr>
                </thead>
                <!-- DataTables <tbody> -->
              </table>
            </div>

            <script>
              var htmlEntityEncode = $.fn.dataTable.render.text().display;

              var line_entry_uri = "";
              $(document).ready(function() {
                var oldStart = 0;
                var windowHeight = $(window).height();

                // Calculate scrollY: Subtract an offset for non-table elements
                var offset = 400;
                var min_scroll_height = 100;
                var scrollYHeight = Math.max(min_scroll_height, windowHeight - offset);  // Ensure minimum of 600px
                var table = $('#pwn_scan_git_source_results').DataTable( {
                  "order": [[2, 'asc']],
                  "scrollY": scrollYHeight + "px",
                  "scrollCollapse": true,
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
                            export_json();
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

                    table.buttons().container().insertAfter('#button_group');
                  }
                });

                $('#pwn_scan_git_source_results tbody').on('click', '.multi_line_select tr', function () {
                  $(this).toggleClass('highlighted');
                });

                // Custom advanced search handling
                $('.dataTables_filter input').unbind();
                $('.dataTables_filter input').on('keyup', function() {
                  var search = $(this).val();

                  var filterFunc;
                  if (search.match(/^\\/.*\\/$/)) {
                    try {
                      var regex = new RegExp(search.slice(1, -1), 'i');
                      filterFunc = function(settings, data, dataIndex) {
                        var rowData = data.join(' ');
                        return regex.test(rowData);
                      };
                    } catch (e) {
                      filterFunc = function(settings, data, dataIndex) {
                        return true;
                      };
                    }
                  } else {
                    var positives = [];
                    var negatives = [];
                    var terms = search.split(/\\s+/).filter(function(t) { return t.length > 0; });
                    for (var i = 0; i < terms.length; i++) {
                      var term = terms[i];
                      if (term.startsWith('-')) {
                        var cleanTerm = term.substring(1).toLowerCase();
                        if (cleanTerm) negatives.push(cleanTerm);
                      } else {
                        positives.push(term.toLowerCase());
                      }
                    }
                    filterFunc = function(settings, data, dataIndex) {
                      var rowData = data.join(' ').toLowerCase();
                      for (var j = 0; j < positives.length; j++) {
                        if (!rowData.includes(positives[j])) return false;
                      }
                      for (var k = 0; k < negatives.length; k++) {
                        if (rowData.includes(negatives[k])) return false;
                      }
                      return true;
                    };
                  }

                  $.fn.dataTable.ext.search.pop();
                  $.fn.dataTable.ext.search.push(filterFunc);
                  table.search('');
                  table.draw();
                });

                // Toggle Columns
                $('a.toggle-vis').on('click', function (e) {
                  e.preventDefault();

                  // Get the column API object
                  var column = table.column( $(this).attr('data-column') );

                  // Toggle the visibility
                  column.visible( ! column.visible() );
                });

                $('#debug_rows_selected').click( function () {
                  alert($('.multi_line_select tr.highlighted').length +' row(s) highlighted');
                });

                // Select All and Deselect All
                function select_deselect_all() {
                  if ($('.multi_line_select tr.highlighted').length === $('.multi_line_select tr').length) {
                    $('.multi_line_select tr.highlighted').removeClass('highlighted');
                  } else {
                    $('.multi_line_select tr:not(.highlighted)').addClass('highlighted');
                  }
                }

                function getExportData() {
                  return new Promise((resolve) => {
                    $.getJSON(table.ajax.url(), function(original_json) {
                      let new_data;
                      if ($('.multi_line_select tr.highlighted').length === 0) {
                        new_data = original_json.data;
                      } else {
                        var selected_results = {};

                        $('.multi_line_select tr.highlighted').each(function() {
                          var inner_tr = $(this);
                          var main_tr = inner_tr.closest('td').parent();
                          var row = table.row(main_tr);
                          var row_index = row.index();
                          var line_index = inner_tr.index();

                          if (selected_results[row_index] === undefined) {
                            selected_results[row_index] = {
                              row: row,
                              lines: []
                            };
                          }

                          selected_results[row_index].lines.push(line_index);
                        });

                        new_data = [];

                        Object.keys(selected_results).forEach(function(ri) {
                          var sel = selected_results[ri];
                          var orig_row_data = sel.row.data();
                          var new_row_data = JSON.parse(JSON.stringify(orig_row_data));

                          sel.lines.sort((a, b) => a - b);
                          new_row_data.line_no_and_contents = sel.lines.map(function(li) {
                            return orig_row_data.line_no_and_contents[li];
                          });

                          new_row_data.raw_content = new_row_data.line_no_and_contents.map(l => l.contents).join('\\n');

                          new_data.push(new_row_data);
                        });
                      }
                      resolve({data: new_data, report_name: original_json.report_name});
                    });
                  });
                }

                function export_json() {
                  if ($('.multi_line_select tr.highlighted').length === 0 && !confirm('No lines selected. Export all records?')) {
                    return;
                  }

                  getExportData().then(({data, report_name}) => {
                    var original_json = {report_name: report_name, data: data};

                    var json_str = JSON.stringify(original_json, null, 2);
                    var blob = new Blob([json_str], { type: 'application/json' });
                    var url = URL.createObjectURL(blob);
                    var a = document.createElement('a');
                    a.href = url;
                    a.download = report_name + '.json';
                    document.body.appendChild(a);
                    a.click();
                    document.body.removeChild(a);
                    URL.revokeObjectURL(url);
                  });
                }

                function export_xlsx_or_pdf(type) {
                  if ($('.multi_line_select tr.highlighted').length === 0 && !confirm('No lines selected. Export all records?')) {
                    return;
                  }

                  getExportData().then(({data, report_name}) => {
                    // Flatten data for export
                    var flatData = [];
                    data.forEach(function(row) {
                      row.line_no_and_contents.forEach(function(line) {
                        flatData.push({
                          timestamp: row.timestamp,
                          test_case: row.security_references.sast_module.split('::')[2],
                          nist: row.security_references.section,
                          cwe: row.security_references.cwe_id,
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
                      // Add title row
                      var titleRow = [{ v: title, t: 's', s: { font: { sz: 14, bold: true }, alignment: { horizontal: 'center' } } }];
                      var ws = XLSX.utils.json_to_sheet(flatData, {skipHeader: true});
                      XLSX.utils.sheet_add_aoa(ws, [titleRow], {origin: 'A1'});
                      XLSX.utils.sheet_add_json(ws, flatData, {origin: 'A2', skipHeader: false});

                      // Merge title cell across columns
                      if (!ws['!merges']) ws['!merges'] = [];
                      ws['!merges'].push({s: {r:0, c:0}, e: {r:0, c:8}}); // A1 to I1

                      // Set column widths by dividing desired column inches by 0.135
                      // column inches observed with Exce
                      // e.g 2.83 inches / 0.135 ~ 209px
                      ws['!cols'] = [
                        {wpx: 209},
                        {wpx: 130},
                        {wpx: 350},
                        {wpx: 40},
                        {wpx: 110},
                        {wpx: 40},
                        {wpx: 370},
                        {wpx: 370},
                        {wpx: 185}
                      ];

                      // Style header row (row 2, since title at 1, header at 2, data from 3)
                      var headerStyle = {
                        font: { bold: true, color: { rgb: "000000" } },
                        fill: { fgColor: { rgb: "999999" } },
                        alignment: { horizontal: 'center', wrapText: true }
                      };
                      for (var col = 0; col < 9; col++) {
                        var cellRef = XLSX.utils.encode_cell({r:1, c:col}); // Row 2 (0-based)
                        if (ws[cellRef]) ws[cellRef].s = headerStyle;
                      }

                      // Alternate row colors for data rows (starting from row 3)
                      var grayFill = { fgColor: { rgb: "DEDEDE" } };
                      var whiteFill = { fgColor: { rgb: "FFFFFF" } };
                      for (var rowNum = 3; rowNum < flatData.length + 2; rowNum++) { // Data rows 2-based from 3
                        var fill = (rowNum % 2 === 0) ? whiteFill : grayFill;
                        for (var col = 0; col < 9; col++) {
                          var cellRef = XLSX.utils.encode_cell({r: rowNum, c: col});
                          if (ws[cellRef]) {
                            if (!ws[cellRef].s) ws[cellRef].s = {};
                            ws[cellRef].s.fill = fill;
                            ws[cellRef].s.alignment = { wrapText: true, vertical: 'top' };
                          }
                        }
                      }

                      // Freeze header
                      ws['!freeze'] = { xSplit: 0, ySplit: 2 };

                      var wb = XLSX.utils.book_new();
                      XLSX.utils.book_append_sheet(wb, ws, 'PWN SAST Results');
                      XLSX.writeFile(wb, report_name + '.xlsx');
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
                                  r.nist,
                                  r.cwe,
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

                // Detect window size changes and recalculate/update scrollY
                $(window).resize(function() {
                  var newWindowHeight = $(window).height();
                  var newScrollYHeight = Math.max(min_scroll_height, newWindowHeight - offset);  // Your offset
                  $('.dt-scroll-body').css('max-height', newScrollYHeight + 'px')
                  table.columns.adjust().draw(false);  // Adjust columns first, then redraw without data reload
                });
              });
            </script>
          </body>
        </html>
        }

        File.open("#{dir_path}/#{report_name}.html", 'w') do |f|
          f.print(html_report)
        end
      rescue StandardError => e
        raise e
      ensure
        spin.stop unless spin.nil?
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
