# frozen_string_literal: true

require 'json'

module PWN
  module Reports
    # This plugin generates Fuzz results from PWN::Plugins::Fuzz.
    # Two files are created, a JSON file containing all of the
    # Fuzz results and an HTML file which is essentially the UI
    # for the JSON file.
    module Fuzz
      # Supported Method Parameters::
      # PWN::Reports::Fuzz.generate(
      #   dir_path: dir_path,
      #   results_hash: results_hash,
      #   char_encoding: 'optional - character encoding returned by PWN::Plugins::Char.list_encoders (defaults to UTF-8)'
      # )

      public_class_method def self.generate(opts = {})
        dir_path = opts[:dir_path].to_s if File.directory?(opts[:dir_path].to_s)
        raise "PWN Error: Invalid Directory #{dir_path}" if dir_path.nil?

        results_hash = opts[:results_hash]
        report_name = results_hash[:report_name]
        opts[:char_encoding].nil? ? char_encoding = 'UTF-8' : char_encoding = opts[:char_encoding].to_s

        # JSON object Completion
        File.open("#{dir_path}/#{report_name}.json", "w:#{char_encoding}") do |f|
          f.print(
            JSON.pretty_generate(results_hash).force_encoding(char_encoding)
          )
        end

        # Report All the Bugs!!! \o/
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
            <script src="//code.jquery.com/jquery-3.6.0.min.js"></script>

            <link rel="stylesheet" type="text/css" href="//cdn.datatables.net/v/dt/dt-1.11.4/b-2.2.2/b-colvis-2.2.2/b-html5-2.2.2/b-print-2.2.2/cr-1.5.5/fc-4.0.1/fh-3.2.1/kt-2.6.4/r-2.2.9/rg-1.1.4/rr-1.2.8/sc-2.0.5/sp-1.4.0/sl-1.3.4/datatables.min.css"/>

            <script type="text/javascript" src="//cdn.datatables.net/v/dt/dt-1.11.4/b-2.2.2/b-colvis-2.2.2/b-html5-2.2.2/b-print-2.2.2/cr-1.5.5/fc-4.0.1/fh-3.2.1/kt-2.6.4/r-2.2.9/rg-1.1.4/rr-1.2.8/sc-2.0.5/sp-1.4.0/sl-1.3.4/datatables.min.js"></script>
          </head>

          <body id="pwn_body">

            <h1 style="display:inline">
              &nbsp;~&nbsp;<a href="https://github.com/0dayinc/pwn/tree/master">pwn network fuzzer</a>
            </h1><br /><br />

            <div><button type="button" id="button">Rows Selected</button></div><br />
            <div>
              <b>Toggle Column(s):</b>&nbsp;
              <a class="toggle-vis" data-column="1" href="#">Timestamp</a>&nbsp;|&nbsp;
              <a class="toggle-vis" data-column="2" href="#">Request</a>&nbsp;|&nbsp;
              <a class="toggle-vis" data-column="3" href="#">Request Encoding</a>&nbsp;|&nbsp;
              <a class="toggle-vis" data-column="3" href="#">Request Length</a>&nbsp;|&nbsp;
              <a class="toggle-vis" data-column="3" href="#">Response</a>&nbsp;|&nbsp;
              <a class="toggle-vis" data-column="3" href="#">Response Length</a>&nbsp;|&nbsp;
            </div>
            <br /><br />

            <div>
              <table id="pwn_fuzz_net_app_proto" class="display squish" cellspacing="0">
                <thead>
                  <tr>
                    <th>#</th>
                    <th>Timestamp</th>
                    <th>Request</th>
                    <th>Request Encoding</th>
                    <th>Request Length</th>
                    <th>Response</th>
                    <th>Response Length</th>
                  </tr>
                </thead>
                <col width="30px" />
                <col width="60px" />
                <col width="300px" />
                <col width="90px" />
                <col width="90px" />
                <col width="300px" />
                <col width="90px" />
                <!-- DataTables <tbody> -->
              </table>
            </div>

            <script>
              var htmlEntityEncode = $.fn.dataTable.render.text().display;

              var line_entry_uri = "";
              $(document).ready(function() {
                var oldStart = 0;
                var table = $('#pwn_fuzz_net_app_proto').DataTable( {
                  "paging": true,
                  "lengthMenu": [10, 25, 50, 100, 250, 500, 1000, 2500, 5000],
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
                  "ajax": "#{report_name}.json",
                  //"deferRender": true,
                  "dom": "fplitfpliS",
                  "autoWidth": false,
                  "fixedColumns": true,
                  "columnDefs": [
                    {
                      targets: 3,
                      className: 'dt-body-center'
                    },
                    {
                      targets: 5,
                      className: 'dt-body-center'
                    }
                  ],
                  "columns": [
                    { "data": null },
                    {
                      "data": "timestamp",
                      "render": $.fn.dataTable.render.text()
                    },
                    {
                      "data": "request",
                      "render": $.fn.dataTable.render.text()
                    },
                    {
                      "data": "request_encoding",
                      "render": $.fn.dataTable.render.text()
                    },
                    {
                      "data": "request_len",
                      "render": $.fn.dataTable.render.text()
                    },
                    {
                      "data": "response",
                      "render": $.fn.dataTable.render.text()
                    },
                    {
                      "data": "response_len",
                      "render": $.fn.dataTable.render.text()
                    }
                  ],
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
                //$('#pwn_fuzz_net_app_proto tbody').on('click', 'tr', function () {
                //  $(this).children('td').children('#multi_line_select').children('tbody').children('tr').toggleClass('highlighted');
                //});

              }
            </script>
          </body>
        </html>
        }

        File.open("#{dir_path}/#{report_name}.html", 'w') do |f|
          f.print(html_report)
        end
      rescue StandardError => e
        raise e
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
            results_hash: results_hash,
            char_encoding: 'optional - character encoding returned by PWN::Plugins::Char.list_encoders (defaults to UTF-8)'
          )

          #{self}.authors
        "
      end
    end
  end
end
