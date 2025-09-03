# frozen_string_literal: true

require 'cgi'
require 'json'
require 'tty-spinner'

module PWN
  module Reports
    # This plugin generates the HTML header and includes external JS/CSS libraries for PWN reports.
    module HTMLFooter
      # Supported Method Parameters::
      # PWN::Reports::HTMLFooter.generate(
      #   column_names: 'required - array of column names to use in the report table',
      #   driver_src_uri: 'required - pwn driver source code uri',
      # )

      public_class_method def self.generate
        %(
                // Select All and Deselect All
                function select_deselect_all() {
                  var visible_multi_line_trs = $('#pwn_results tbody tr:visible .multi_line_select tr');
                  var highlighted_in_visible = visible_multi_line_trs.filter('.highlighted');
                  if (highlighted_in_visible.length === visible_multi_line_trs.length) {
                    highlighted_in_visible.removeClass('highlighted');
                  } else {
                    visible_multi_line_trs.filter(':not(.highlighted)').addClass('highlighted');
                  }
                }

                function getExportData(table) {
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

                function export_json(table) {
                  if ($('.multi_line_select tr.highlighted').length === 0 && !confirm('No lines selected. Export all records?')) {
                    return;
                  }

                  getExportData(table).then(({data, report_name}) => {
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

                // Custom advanced search handling
                $('#dt-search-0').unbind();
                $('#dt-search-0').on('input', function() {
                  var table = $('#pwn_results').DataTable();
                  var searchTerm = this.value;
                  var isRegex = false;
                  var isSmart = true;
                  table.search(searchTerm, isRegex, isSmart).draw();
                });

                // Toggle Columns
                $('a.toggle-vis').on('click', function (e) {
                  var table = $('#pwn_results').DataTable();
                  e.preventDefault();

                  // Get the column API object
                  var column = table.column( $(this).attr('data-column') );

                  // Toggle the visibility
                  column.visible( ! column.visible() );
                });

                // Row highlighting for multi-line selection
                $('#pwn_results').on('click', '.multi_line_select tr', function () {
                  $(this).toggleClass('highlighted');
                });

                // Detect window size changes and recalculate/update scrollY
                $(window).resize(function() {
                  var table = $('#pwn_results').DataTable();
                  var newWindowHeight = $(window).height();
                  var newScrollYHeight = Math.max(min_scroll_height, newWindowHeight - offset);  // Your offset
                  $('.dt-scroll-body').css('max-height', newScrollYHeight + 'px')
                  table.columns.adjust().draw(false);  // Adjust columns first, then redraw without data reload
                  console.log('Window resized. New scrollY height: ' + newScrollYHeight + 'px');
                });
            </script>
          </body>
        </html>
        )
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
            column_names: 'Array of Column Names to use in the report table',
            driver_src_uri: 're

          #{self}.authors
        "
      end
    end
  end
end
