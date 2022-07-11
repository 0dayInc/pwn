# frozen_string_literal: true

require 'json'

module PWN
  module Reports
    # This plugin generates the Static Code Anti-Pattern Matching Analysis
    # results within the root of a given source repo.  Two files are created,
    # a JSON file containing all of the SAST results and an HTML file
    # which is essentially the UI for the JSON file.
    module SAST
      # Supported Method Parameters::
      # PWN::Reports::SAST.generate(
      #   dir_path: dir_path,
      #   results_hash: results_hash
      # )

      public_class_method def self.generate(opts = {})
        dir_path = opts[:dir_path].to_s if File.directory?(opts[:dir_path].to_s)
        raise "PWN Error: Invalid Directory #{dir_path}" if dir_path.nil?

        results_hash = opts[:results_hash]

        # JSON object Completion
        # File.open("#{dir_path}/pwn_scan_git_source.json", 'w') do |f|
        #   f.print(results_hash.to_json)
        # end
        File.write(
          "#{dir_path}/pwn_scan_git_source.json",
          JSON.pretty_generate(results_hash)
        )

        html_report = %q{<!DOCTYPE HTML>
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
              }

              .highlighted {
                background-color: #F2F5A9 !important;
              }
            </style>

            <!-- jQuery & DataTables -->
            <script type="text/javascript" src="//code.jquery.com/jquery-3.6.0.min.js"></script>

            <link rel="stylesheet" type="text/css" href="//cdn.datatables.net/v/dt/dt-1.11.4/b-2.2.2/b-colvis-2.2.2/b-html5-2.2.2/b-print-2.2.2/cr-1.5.5/fc-4.0.1/fh-3.2.1/kt-2.6.4/r-2.2.9/rg-1.1.4/rr-1.2.8/sc-2.0.5/sp-1.4.0/sl-1.3.4/datatables.min.css"/>

            <script type="text/javascript" src="//cdn.datatables.net/v/dt/dt-1.11.4/b-2.2.2/b-colvis-2.2.2/b-html5-2.2.2/b-print-2.2.2/cr-1.5.5/fc-4.0.1/fh-3.2.1/kt-2.6.4/r-2.2.9/rg-1.1.4/rr-1.2.8/sc-2.0.5/sp-1.4.0/sl-1.3.4/datatables.min.js"></script>
          </head>

          <body id="pwn_body">

            <h1 style="display:inline">
              <a href="https://github.com/0dayinc/pwn/tree/master">~ pwn sast</a>
            </h1><br /><br />
            <h2 id="report_name"></h2><br />

            <div><button type="button" id="button">Rows Selected</button></div><br />
            <div>
              <b>Toggle Column(s):</b>&nbsp;
              <a class="toggle-vis" data-column="1" href="#">Timestamp</a>&nbsp;|&nbsp;
              <a class="toggle-vis" data-column="2" href="#">Test Case / Security Requirements</a>&nbsp;|&nbsp;
              <a class="toggle-vis" data-column="3" href="#">Path</a>&nbsp;|&nbsp;
              <a class="toggle-vis" data-column="4" href="#">Line#, Formatted Content, &amp; Last Committed By</a>&nbsp;|&nbsp;
              <a class="toggle-vis" data-column="5" href="#">Raw Content</a>&nbsp;|&nbsp;
              <a class="toggle-vis" data-column="6" href="#">Test Case (Anti-Pattern) Filter</a>
            </div>
            <br /><br />

            <div>
              <table id="pwn_scan_git_source_results" class="display" cellspacing="0">
                <thead>
                  <tr>
                    <th>#</th>
                    <th>Timestamp</th>
                    <th>Test Case / Security Requirements</th>
                    <th>Path</th>
                    <th>Line#, Formatted Content, &amp; Last Committed By</th>
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
                var table = $('#pwn_scan_git_source_results').DataTable( {
                  "paging": true,
                  "pagingType": "full_numbers",
                  "fnDrawCallback": function ( oSettings ) {
                    /* Need to redo the counters if filtered or sorted */
                    if ( oSettings.bSorted || oSettings.bFiltered ) {
                      for ( var i=0, iLen=oSettings.aiDisplay.length ; i<iLen ; i++ ) {
                        $('td:eq(0)', oSettings.aoData[ oSettings.aiDisplay[i] ].nTr ).html( i+1 );
                      }
                    }
                    // Jump to top when utilizing pagination
                    if ( oSettings._iDisplayStart != oldStart ) {
                      var targetOffset = $('#pwn_body').offset().top;
                      $('html,body').animate({scrollTop: targetOffset}, 500);
                      oldStart = oSettings._iDisplayStart;
                    }
                    // Select individual lines in a row
                    $('#multi_line_select tbody').on('click', 'tr', function () {
                      $(this).toggleClass('highlighted');
                      if ($('#multi_line_select tr.highlighted').length > 0) {
                        $('#multi_line_select tr td button').attr('disabled', 'disabled');
                        // Remove multi-line bug button
                      } else {
                        $('#multi_line_select tr td button').removeAttr('disabled');
                        // Add multi-line bug button
                      }
                    });
                  },
                  "ajax": "pwn_scan_git_source.json",
                  //"deferRender": true,
                  "dom": "fplitfpliS",
                  "autoWidth": false,
                  "columns": [
                    { "data": null },
                    {
                      "data": "timestamp",
                      "render": $.fn.dataTable.render.text()
                    },
                    {
                      "data": "security_requirements",
                      "render": function (data, type, row, meta) {
                        var sast_dirname = data['sast_module'].split('::')[0].toLowerCase() + '/' + data['sast_module'].split('::')[1].toLowerCase();
                        var sast_module = data['sast_module'].split('::')[2];
                        var sast_test_case = sast_module.replace(/\.?([A-Z])/g, function (x,y){ if (sast_module.match(/\.?([A-Z][a-z])/g) ) { return "_" + y.toLowerCase(); } else { return y.toLowerCase(); } }).replace(/^_/g, "");

                        return '<tr><td style="width:150px;" align="left"><a href="https://github.com/0dayinc/pwn/tree/master/lib/' + htmlEntityEncode(sast_dirname) + '/' + htmlEntityEncode(sast_test_case) + '.rb" target="_blank">' + htmlEntityEncode(data['sast_module'].split("::")[2]) + '</a><br /><br /><a href="' + htmlEntityEncode(data['nist_800_53_uri']) + '" target="_blank">NIST 800-53: ' + htmlEntityEncode(data['section'])  + '</a><br /><br /><a href="' + htmlEntityEncode(data['cwe_uri']) + '" target="_blank">CWE:' + htmlEntityEncode(data['cwe_id'])  + '</a></td></tr>';
                      }
                    },
                    {
                      "data": "filename",
                      "render": function (data, type, row, meta) {
                        line_entry_uri = htmlEntityEncode(
                          data['git_repo_root_uri'] + '/' + data['entry']
                        );

                        file = htmlEntityEncode(data['entry']);

                        return '<table class="squish"><tr class="highlighted"><td style="width:150px;" align="left"><a href="' + line_entry_uri + '" target="_blank">' + file + '</a></td></tr></table>';
                      }
                    },
                    {
                      "data": "line_no_and_contents",
                      "render": function (data, type, row, meta) {
                        var pwn_rows = '<td style="width: 669px"><table id="multi_line_select" class="display squish" style="width: 665px"><tbody>';
                        for (var i = 0; i < data.length; i++) {
                          var tr_class;
                          if (i % 2 == 0) { tr_class = "odd"; } else { tr_class = "even"; }

                          var filename_link = row.filename;

                          var bug_comment = 'Timestamp: ' + row.timestamp + '\n' +
                                            'Test Case: http://' + window.location.hostname + ':8808/doc_root/pwn-0.1.0/' +
                                              row.security_requirements['sast_module'].replace(/::/g, "/") + '\n' +
                                            'Source Code Impacted: ' + $("<div/>").html(filename_link).text() + '\n\n' +
                                            'Test Case Request:\n' +
                                            $("<div/>").html(row.test_case_filter.replace(/\s{2,}/g, " ")).text() + '\n\n' +
                                            'Test Case Response:\n' +
                                            '\tCommitted by: ' + $("<div/>").html(data[i]['author']).text() + '\t' +
                                              data[i]['line_no'] + ': ' +
                                              $("<div/>").html(data[i]['contents'].replace(/\s{2,}/g, " ")).text() + '\n\n';

                          var author_and_email_arr = data[i]['author'].split(" ");
                          var email = author_and_email_arr[author_and_email_arr.length - 1];
                          var email_user_arr = email.split("@");
                          var assigned_to = email_user_arr[0].replace("&lt;", "");

                          var uri = '#uri';

                         var canned_email_results = 'Timestamp: ' + row.timestamp + '\n' +
                                                    'Source Code File Impacted: ' + $("<div/>").html(filename_link).text() + '\n\n' +
                                                    'Source Code in Question:\n\n' +
                                                    data[i]['line_no'] + ': ' +
                                                    $("<div/>").html(data[i]['contents'].replace(/\s{2,}/g, " ")).text() + '\n\n';

                         var canned_email = email.replace("&lt;", "").replace("&gt;", "") + '?subject=Potential%20Bug%20within%20Source%20File:%20'+ encodeURIComponent(row.filename) +'&body=Greetings,%0A%0AThe%20following%20information%20likely%20represents%20a%20bug%20discovered%20through%20automated%20security%20testing%20initiatives:%0A%0A' + encodeURIComponent(canned_email_results) + 'Is%20this%20something%20that%20can%20be%20addressed%20immediately%20or%20would%20filing%20a%20bug%20be%20more%20appropriate?%20%20Please%20let%20us%20know%20at%20your%20earliest%20convenience%20to%20ensure%20we%20can%20meet%20security%20expectations%20for%20this%20release.%20%20Thanks%20and%20have%20a%20great%20day!';

                          domain = line_entry_uri.replace('http://','').replace('https://','').split(/[/?#]/)[0];
                          if (domain.includes('stash')) {
                            to_line_number = line_entry_uri + '#' + data[i]['line_no'];
                          } else {
                            to_line_number = line_entry_uri + '#L' + data[i]['line_no'];
                          }

                          pwn_rows = pwn_rows.concat('<tr class="' + tr_class + '"><td style="width:90px" align="left"><a href="' + htmlEntityEncode(to_line_number) + '" target="_blank">' + htmlEntityEncode(data[i]['line_no']) + '</a>:&nbsp;</td><td style="width:300px" align="left">' + htmlEntityEncode(data[i]['contents']) + '</td><td style="width:200px" align="right"><a href="mailto:' + canned_email + '">' + htmlEntityEncode(data[i]['author']) + '</a></td></tr>');
                        }
                        pwn_rows = pwn_rows.concat('</tbody></table></td>');
                        return pwn_rows;
                      }
                    },
                    {
                      "data": "raw_content",
                      "render": $.fn.dataTable.render.text()
                    },
                    {
                      "data": "test_case_filter",
                      "render": $.fn.dataTable.render.text()
                    }
                  ]
                });
                // Toggle Columns
                $('a.toggle-vis').on('click', function (e) {
                  e.preventDefault();

                  // Get the column API object
                  var column = table.column( $(this).attr('data-column') );

                  // Toggle the visibility
                  column.visible( ! column.visible() );
                });

                // TODO: Open bug for highlighted rows ;)
                $('#button').click( function () {
                  alert($('#multi_line_select tr.highlighted').length +' row(s) highlighted');
                });
              });

              function multi_line_select() {
                // Select all lines in a row
                //$('#pwn_scan_git_source_results tbody').on('click', 'tr', function () {
                //  $(this).children('td').children('#multi_line_select').children('tbody').children('tr').toggleClass('highlighted');
                //});

              }
            </script>
          </body>
        </html>
        }

        File.open("#{dir_path}/pwn_scan_git_source.html", 'w') do |f|
          f.print(html_report)
        end
      rescue StandardError => e
        raise e
      end

      # Author(s):: 0day Inc. <request.pentest@0dayinc.com>

      public_class_method def self.authors
        "AUTHOR(S):
          0day Inc. <request.pentest@0dayinc.com>
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
