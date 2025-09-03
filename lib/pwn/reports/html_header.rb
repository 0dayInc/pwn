# frozen_string_literal: true

require 'cgi'
require 'json'
require 'tty-spinner'

module PWN
  module Reports
    # This plugin generates the HTML header and includes external JS/CSS libraries for PWN reports.
    module HTMLHeader
      # Supported Method Parameters::
      # PWN::Reports::HTMLHeader.generate(
      #   column_names: 'required - array of column names to use in the report table',
      #   driver_src_uri: 'required - pwn driver source code uri',
      # )

      public_class_method def self.generate(opts = {})
        column_names = opts[:column_names] || []
        driver_src_uri = opts[:driver_src_uri]
        raise 'ERROR: :driver_src_uri must be provided' if driver_src_uri.nil? || driver_src_uri.strip == ''

        driver_src_name = "~ #{driver_src_uri.to_s.split('/').last.gsub('_', ' ')}"

        external_css_libraries = [
          {
            src: 'https://cdn.datatables.net/plug-ins/2.3.3/features/searchHighlight/dataTables.searchHighlight.css',
            integrity: 'sha384-3FGcHDS9wKlVV/Pu4y1kojpLsNxlE3jQjdm1N0p7RC9f6xPdRAj78js3ELGiGP/j'
          },
          {
            src: 'https://cdn.datatables.net/v/dt/jszip-3.10.1/dt-2.3.3/b-3.2.4/b-colvis-3.2.4/b-html5-3.2.4/b-print-3.2.4/fc-5.0.4/fh-4.0.3/kt-2.12.1/r-3.0.6/rg-1.5.2/rr-1.5.0/sc-2.4.3/sb-1.8.3/sp-2.3.5/sl-3.1.0/datatables.min.css',
            integrity: 'sha384-51NLFpi/9qR2x0LAjQHiFAjV765f0g9+05EmKQ/QWINR/y3qonty8mPy68vEbo0z'
          }
        ]

        external_js_libraries = [
          {
            src: 'https://code.jquery.com/jquery-3.7.1.min.js',
            integrity: 'sha256-/JqT3SQfawRcv/BIHPThkBvs0OEvtFFmqPF/lYI/Cxo='
          },
          {
            src: 'https://cdn.jsdelivr.net/npm/datatables.mark.js@2.1.0/dist/datatables.mark.min.js',
            integrity: 'sha384-1NNYvadWgPeE3tcSCdnI+3HB9iVqXwDBQsQUCUJTygTR3Whmz3HFkMn1kdevXe/F'
          },
          {
            src: 'https://bartaz.github.io/sandbox.js/jquery.highlight.js',
            integrity: 'sha384-COfjQfuLZw+Zvx+XMsYIVqsBHXPaUJnu/nwutbZvnI3zys8lUt3N3SUDsR6yu7ud'
          },
          {
            src: 'https://cdnjs.cloudflare.com/ajax/libs/pdfmake/0.2.7/pdfmake.min.js',
            integrity: 'sha384-VFQrHzqBh5qiJIU0uGU5CIW3+OWpdGGJM9LBnGbuIH2mkICcFZ7lPd/AAtI7SNf7'
          },
          {
            src: 'https://cdnjs.cloudflare.com/ajax/libs/pdfmake/0.2.7/vfs_fonts.js',
            integrity: 'sha384-/RlQG9uf0M2vcTw3CX7fbqgbj/h8wKxw7C3zu9/GxcBPRKOEcESxaxufwRXqzq6n'
          },
          {
            src: 'https://cdn.datatables.net/v/dt/jszip-3.10.1/dt-2.3.3/b-3.2.4/b-colvis-3.2.4/b-html5-3.2.4/b-print-3.2.4/fc-5.0.4/fh-4.0.3/kt-2.12.1/r-3.0.6/rg-1.5.2/rr-1.5.0/sc-2.4.3/sb-1.8.3/sp-2.3.5/sl-3.1.0/datatables.min.js',
            integrity: 'sha384-jvnxkXTB++rTO/pbg6w5nj0jm5HiSGtTcBW5vnoLGRfmSxw3eyqNA0bJ+m6Skjw/'
          },
          {
            src: 'https://cdn.datatables.net/plug-ins/2.3.3/features/searchHighlight/dataTables.searchHighlight.min.js',
            integrity: 'sha384-XDdmvsWg5e1/POTILjMFvB3KtrBqRk5W1CG9aoi1+K6bBMPHQAvlKEiekndU6CTp'
          },
          {
            src: 'https://unpkg.com/exceljs@4.4.0/dist/exceljs.min.js',
            integrity: 'sha384-Pqp51FUN2/qzfxZxBCtF0stpc9ONI6MYZpVqmo8m20SoaQCzf+arZvACkLkirlPz'
          }
        ]

        markup = %(<!DOCTYPE HTML>
        <html>
          <head>
            <!-- favicon.ico from https://0dayinc.com -->
            <link rel="icon" href="data:image/x-icon;base64,AAABAAEAEBAAAAEAIABoBAAAFgAAACgAAAAQAAAAIAAAAAEAIAAAAAAAAAQAABIXAAASFwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAIkAAACJAgAAiSYAAIlbAACJcAAAiX0AAIlmAACJLQAAiQQAAIkAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAIkAAACJAAAAiS0AAIluAACJdwAAiXgAAIl+AACJeAAAiXQAAIk5AACJAQAAiQAAAAAAAAAAAAAAAAAAAAAAAACJAAAAiRgAAIlvAACJbQAAiXcAAIl7AACJcwAAiXEAAIl1AACJZwAAiR4AAIkAAACJAAAAAAAAAAAAAACJAAAAiQAAAIlEAACJfAAAiXIAAIlyAACJewAAiX4AAIl5AACJdQAAiXcAAIlIAACJAAAAiQAAAAAAAAAAAAAAiQAAAIkJAACJWQAAiXUAAIl9AACJdAAAiYYAAImLAACJdAAAiXkAAImNAACJfQAAiQwAAIkAAAAAAAAAAAAAAIkAAACJFQAAiWsAAIl2AACJfAAAiYIAAImCAACJfwAAiXYAAIl5AACJiQAAiYYAAIkWAACJAAAAAAAAAAAAAACJAAAAiSAAAIl2AACJeQAAiXkAAIl1AACJfwAAiYEAAIl8AACJbwAAiXoAAImBAACJFgAAiQAAAAAAAAAAAAAAiQAAAIkpAACJeAAAiXMAAIl3AACJeQAAiXUAAImAAACJfwAAiWYAAIl4AACJfwAAiR4AAIkAAAAAAAAAAAAAAIkAAACJKAAAiXkAAIlyAACJdQAAiXQAAIluAACJfAAAiXwAAIl3AACJewAAiXwAAIkvAACJAAAAAAAAAAAAAACJAAAAiSMAAIl4AACJdgAAiXsAAIl1AACJcQAAiXcAAIl6AACJeQAAiXoAAIl0AACJKQAAiQAAAAAAAAAAAAAAiQAAAIkXAACJaAAAiXgAAIl3AACJfAAAiXkAAIl3AACJZwAAiXcAAIl0AACJagAAiSgAAIkAAAAAAAAAAAAAAIkAAACJDgAAiV4AAIl5AACJbwAAiW4AAIl9AACJewAAiXcAAIl6AACJfQAAiW8AAIkWAACJAAAAAAAAAAAAAACJAAAAiQ0AAIllAACJewAAiXYAAIl4AACJdQAAiXUAAIl4AACJbQAAiXkAAIlNAACJAwAAiQAAAAAAAAAAAAAAiQAAAIkCAACJPQAAiXMAAIl2AACJeAAAiWgAAIlsAACJfQAAiXsAAIlwAACJGQAAiQAAAIkAAAAAAAAAAAAAAAAAAACJAAAAiQcAAIk4AACJXAAAiXoAAIl7AACJfAAAiYAAAIlsAACJJwAAiQMAAIkAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAIkAAACJAQAAiSsAAIluAACJewAAiXwAAIluAACJKgAAiQAAAIkAAAAAAAAAAAAAAAAA8A8AAPAHAADgBwAA4AcAAMADAADAAwAAwAMAAMADAADAAwAAwAMAAMADAADAAwAAwAMAAMAHAADgBwAA8B8AAA==" type="image/x-icon" />
            <style>
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

              body {
                font-family: Verdana, Geneva, sans-serif;
                font-size: 11px;
                background-color: #FFFFFF;
                color: #084B8A !important;
                margin: 3px 3px 3px 3px !important;
                padding: 0px 0px 0px 0px !important;
                overflow-y: hidden;
                min-height: 100vh !important;
                height: 100% !important;
              }

              div.toggle_col_and_button_group {
                display: flex; /* Makes the container a flex container */
                justify-content: none; /* Aligns items along the main axis */
                align-items: flex-start; /* Aligns items to the start of the cross-axis */
                width: 1275px !important;
              }

              div.cols_to_toggle {
                width: 855px !important;
                text-align: left !important;
                vertical-align: middle !important;
              }

              div.dt-buttons {
                width: 420px !important;
                text-align: right !important;
              }

              div.dt-container {
                min-height: 100vh !important;
                height: 100% !important;
                width: 1275px !important;
              }

              div.dt-scroll-body {
                width: 1275px !important;
              }

              span.highlight {
                background-color: cyan  !important;
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
        )

        external_css_libraries.each do |css_lib_hash|
          css_lib = css_lib_hash[:src]
          css_integrity = css_lib_hash[:integrity]
          markup += %(
            <link href="#{css_lib}" rel="stylesheet" integrity="#{css_integrity}" crossorigin="anonymous">
          )
        end

        external_js_libraries.each do |js_lib|
          js_src = js_lib[:src]
          js_integrity = js_lib[:integrity]
          markup += %(
            <script type="text/javascript" src="#{js_src}" integrity="#{js_integrity}" crossorigin="anonymous"></script>
          )
        end

        markup += %(
          </head>
          <body id="pwn_body">

            <h1 style="display:inline">
              <img src="data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAIEAAACCCAQAAADLPWN1AAAAAXNSR0IB2cksfwAAAARnQU1BAACxjwv8YQUAAAAgY0hSTQAAeiYAAICEAAD6AAAAgOgAAHUwAADqYAAAOpgAABdwnLpRPAAAAAJiS0dEAIKpO8E+AAAACXBIWXMAAAsTAAALEwEAmpwYAAADTElEQVR42u2dyY7jMBBDqxrz/7+sOTRycCKJpOwBBsjzrWO3F4Ks3XKPUV++/dTXb3+qqjr8p1/i9HLPa2uxZ0z+6s011HXPngMWAAEQvGzBXK+fW6b+uUJ7ebTWuL7+yXPAAiB4E8IdurV5XObs1rLQEZ37HLAACKZCcLcrIe8QXFF7wAKEAAT/sS2oSWbnuqUOz55dFxYAwQNCyKi1iwdbuEudOq0j0A6jUlgABLYQ+saJVP1vHB1X0XFnzwELgAAIXrbgLMLS3YS2LMdZoWO2b8AChPB0mjRLQ9okX9tSWcuiTUepos2dbGmoIYSLEDRxXYur+0Pne3bRYZv3OXtCWAAEQFBGyUSVPa52ZCydZ5lO1tXz7nwl7xYWAMGbD/ocumvTEenUpc0oci2sLM4zHndyNCwAgjchtJlyKOK6SUt8s5GkdAxLmoQQgOCeU8wyOzevHNFv6fkomSAEu2Qyo4xKk3QXOROWS/fZddOBf1gABDI67JC4KkrLxmt3tQv3v1qKAxYAARBcbUE6OZzZhzKjtCzeO7MSRXSIEM7SJOWiRljOUCR1644loz7teBECQrikSSUJqbtESg6usLKY0+9E9fIasAAIgKA2M8juaNXM3eiO8RN5IywAgn8aHaoE5XTZjJNoUzvo7FqUTBCCIYQsQXKjSHdk485c+lnNkjQJIQDBzha4M4ZnTjGr+9fyumddbjrLCGGTJqWlEHeecOaclHx091rf3/o3OssIwagXeHTzaazjzKySoGoSPZUPLAACIHiiZDJu6F5Flm6mmHavVXZLdIgQ7OjQXZVGL+2kSe+ObHREc7ejDQuA4G0VCzcNcY+bRXPKgj9RhchqErAACICgNivjP1fDc2dJynSe2vWt+xyz54AFQBAu7ZS2vLJFNmbnc1t86RvRsAAITI+gBXG2LLyb6gzhiTqscTQsQAhAIG3BmcPyoj3nfCOKIl3b4rp1WAAEt76Vso4En3gXWb39nA7yUzJBCKEQUnvuRXO741Qi41r8sxEQWAAEQHDPFqy/cjduaPzsrbX1ne3WY4QFQLARwtMvQWWLx6VncqPX9W+wAAge/FbK2p5nn6PU4x6uRNzCOiwAAiCozdwhLAACIPiq7S/uVkwm4fz8nQAAAABJRU5ErkJggg==" type="image/png" style="iheight:70px;width:70px;"/>
              <a href="#{driver_src_uri}" target="_blank">#{driver_src_name}</a>
            </h1>
            <h2 id="report_name"></h2><br />

            <div id="toggle_col_and_button_group" class="toggle_col_and_button_group">
              <div class="cols_to_toggle">
                <b>Toggle Column(s) Visibility:</b>&nbsp;
        )

        last_column_idx = column_names.length - 1
        column_names.each_with_index do |col, idx|
          dat_col = idx + 1
          encoded_col = CGI.escape_html(col)
          if idx < last_column_idx
            markup += %(
                <a class="toggle-vis" data-column="#{dat_col}" href="#">#{encoded_col}</a>&nbsp;|&nbsp;
            )
          else
            markup += %(
                <a class="toggle-vis" data-column="#{dat_col}" href="#">#{encoded_col}</a>
            )
          end
        end

        markup += %(
              </div>
            </div>
            <div class="dt-container">
              <table id="pwn_results" class="display" cellspacing="0">
                <thead>
                  <tr>
                    <th>#</th>
        )

        column_names.each do |col|
          markup += %(
            <th>#{col}</th>
          )
        end

        markup += %(
                  </tr>
                </thead>
                <!-- DataTables <tbody> -->
              </table>
            </div>
            <script>
              var htmlEntityEncode = $.fn.dataTable.render.text().display;
              var line_entry_uri = "";
              var oldStart = 0;
              var windowHeight = $(window).height();

              // Calculate scrollY: Subtract an offset for non-table elements
              var offset = 325;
              var min_scroll_height = 50;
              var scrollYHeight = Math.max(min_scroll_height, windowHeight - offset);  // Ensure minimum of 600px
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
