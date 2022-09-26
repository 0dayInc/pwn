# frozen_string_literal: true

require 'json'

module PWN
  module Reports
    # This plugin generates the War Dialing results produced by pwn_phone.
    module Phone
      # Supported Method Parameters::
      # PWN::Reports::Phone.generate(
      #   dir_path: dir_path,
      #   results_hash: results_hash
      # )

      public_class_method def self.generate(opts = {})
        dir_path = opts[:dir_path].to_s if File.directory?(opts[:dir_path].to_s)
        raise "PWN Error: Invalid Directory #{dir_path}" if dir_path.nil?

        results_hash = opts[:results_hash]

        File.write(
          "#{dir_path}/pwn_phone.json",
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

            <!-- jQuery, DataTables, & FancyApps -->
            <script type="text/javascript" src="//code.jquery.com/jquery-3.6.0.min.js"></script>

            <link rel="stylesheet" type="text/css" href="//cdn.datatables.net/v/dt/dt-1.11.4/b-2.2.2/b-colvis-2.2.2/b-html5-2.2.2/b-print-2.2.2/cr-1.5.5/fc-4.0.1/fh-3.2.1/kt-2.6.4/r-2.2.9/rg-1.1.4/rr-1.2.8/sc-2.0.5/sp-1.4.0/sl-1.3.4/datatables.min.css"/>

            <script type="text/javascript" src="//cdn.datatables.net/v/dt/dt-1.11.4/b-2.2.2/b-colvis-2.2.2/b-html5-2.2.2/b-print-2.2.2/cr-1.5.5/fc-4.0.1/fh-3.2.1/kt-2.6.4/r-2.2.9/rg-1.1.4/rr-1.2.8/sc-2.0.5/sp-1.4.0/sl-1.3.4/datatables.min.js"></script>

            <link rel="stylesheet" href="//cdn.jsdelivr.net/npm/@fancyapps/ui@4.0/dist/fancybox.css" type="text/css" />

            <script type="text/javascript" src="//cdn.jsdelivr.net/npm/@fancyapps/ui@4.0/dist/fancybox.umd.js"></script>
          </head>

          <body id="pwn_body">

            <h1 style="display:inline">
              <a href="https://github.com/0dayinc/pwn/tree/master">~ pwn phone</a>
            </h1><br /><br />
            <h2 id="report_name"></h2><br />

            <div><button type="button" id="button">Rows Selected</button></div><br />
            <div>
              <b>Toggle Column(s):</b>&nbsp;
              <a class="toggle-vis" data-column="1" href="#">Call Started</a>&nbsp;|&nbsp;
              <a class="toggle-vis" data-column="2" href="#">Source #</a>&nbsp;|&nbsp;
              <a class="toggle-vis" data-column="3" href="#">Source # Rules</a>&nbsp;|&nbsp;
              <a class="toggle-vis" data-column="4" href="#">Target #</a>&nbsp;|&nbsp;
              <a class="toggle-vis" data-column="5" href="#">Seconds Recorded</a>&nbsp;|&nbsp;
              <a class="toggle-vis" data-column="6" href="#">Call Stopped</a>
              <a class="toggle-vis" data-column="7" href="#">Reason</a>
              <a class="toggle-vis" data-column="8" href="#">Screenlog</a>&nbsp;|&nbsp;
              <a class="toggle-vis" data-column="9" href="#">Recording</a>&nbsp;|&nbsp;
              <a class="toggle-vis" data-column="10" href="#">Spectrogram</a>&nbsp;|&nbsp;
              <a class="toggle-vis" data-column="11" href="#">Waveform</a>
            </div>
            <br /><br />

            <div>
              <table id="pwn_phone_results" class="display" cellspacing="0">
                <thead>
                  <tr>
                    <th>#</th>
                    <th>Call Started</th>
                    <th>Source #</th>
                    <th>Source # Rules</th>
                    <th>Target #</th>
                    <th>Seconds Recorded</th>
                    <th>Call Stopped</th>
                    <th>Reason Stopped</th>
                    <th>Screenlog</th>
                    <th>Recording</th>
                    <th>Spectrogram</th>
                    <th>Waveform</th>
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
                var table = $('#pwn_phone_results').DataTable( {
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
                  "ajax": "pwn_phone.json",
                  //"deferRender": true,
                  "dom": "fplitfpliS",
                  "autoWidth": false,
                  "columns": [
                    { "data": null },
                    {
                      "data": "call_started",
                      "render": $.fn.dataTable.render.text()
                    },
                    {
                      "data": "src_num",
                      "render": $.fn.dataTable.render.text()
                    },
                    {
                      "data": "src_num_rules",
                      "render": $.fn.dataTable.render.text()
                    },
                    {
                      "data": "target_num",
                      "render": $.fn.dataTable.render.text()
                    },
                    {
                      "data": "seconds_recorded",
                      "render": $.fn.dataTable.render.text()
                    },
                    {
                      "data": "call_stopped",
                      "render": $.fn.dataTable.render.text()
                    },
                    {
                      "data": "reason",
                      "render": $.fn.dataTable.render.text()
                    },
                    {
                      "data": "screenlog",
                      "render": function (data, type, row, meta) {
                        var screenlog = htmlEntityEncode(data);
                        return '<a href="' + screenlog +'" target="_blank">' + screenlog + '</a>';
                      }
                    },
                    {
                      "data": "recording",
                      "render": function (data, type, row, meta) {
                        var wav = htmlEntityEncode(data);
                        if (wav == '--') {
                          return wav;
                        } else {
                          return '<audio controls><source src="' + wav +'" type="audio/wav"></audio>';
                        }
                      }
                    },
                    {
                      "data": "spectrogram",
                      "render": function (data, type, row, meta) {
                        var spt = htmlEntityEncode(data);
                        if (spt == '--') {
                          return spt;
                        } else {
                          return '<a data-fancybox data-src="' + spt + '" data-caption="' + spt + '"><img src="' + data +'" target="_blank" style="width:150px; height:150px;"/></a>';
                        }
                      }
                    },
                    {
                      "data": "waveform",
                      "render": function (data, type, row, meta) {
                        var wfm = htmlEntityEncode(data);
                        if (wfm == '--') {
                          return wfm;
                        } else {
                          return '<a data-fancybox data-src="' + wfm + '" data-caption="' + wfm + '"><img src="' + data +'" target="_blank" style="width:150px; height:150px;"/></a>';
                        }
                      }
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
                //$('#pwn_phone_results tbody').on('click', 'tr', function () {
                //  $(this).children('td').children('#multi_line_select').children('tbody').children('tr').toggleClass('highlighted');
                //});

              }
            </script>
          </body>
        </html>
        }

        File.open("#{dir_path}/pwn_phone.html", 'w') do |f|
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
