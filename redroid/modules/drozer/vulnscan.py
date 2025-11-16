#!/usr/bin/env python3
"""
Drozer Vulnerability Scanning
"""

import os
import subprocess
import datetime
from colorama import Fore, Style
import redroid.config as config

def drozer_vulnscan():
    # global config.target_app
    html_begin = "<html><head><title>APP Analysis Report</title></head><body><h1 style=\"text-align: center;\"><strong>Drozer Analysis Report</strong></h1>"
    separator = "_" * 100 + "\n"
    
    if not config.target_app:
        print(Fore.YELLOW + "⚠️ No target app set. Please select a target app first." + Style.RESET_ALL)
        set_target_app()
        if not config.target_app:
            print(Fore.RED + "❌ No target app selected. Aborting scan." + Style.RESET_ALL)
            return
    
    p_name = config.target_app
    print(Fore.GREEN + f"Using target app: {p_name}" + Style.RESET_ALL)
    
    file_name = input("Enter the file name to store the results: ")
    f_json = file_name + ".json"
    f_html = file_name + ".html"
    
    def perform_scan(query_type, p_name, a=0):
        drozer_command = 'drozer console connect -c "run ' + str(query_type) + ' ' + str(p_name) + '"'
        if a == 1:
            drozer_command = 'drozer console connect -c "run ' + str(query_type) + ' "'
        process = subprocess.Popen(drozer_command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                   shell=True, universal_newlines=True)
        input_stream, output_stream = process.stdin, process.stdout
        process_data = output_stream.read()
        input_stream.close()
        output_stream.close()
        process.wait()
        if process_data.find("could not find the package") != -1:
            process_data = 'Invalid Package'
        return process_data

    def format_data(task, result, file_name):
        nonlocal html_begin
        html_out = 1
        sep = "*" * 50
        print(Fore.GREEN + "\n%s:\n%s\n%s" % (task, sep, result))
        result_html = result.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;") \
                            .replace("\\n", "<br>").replace("\\r", "")
        final_res = {str(task): result_html}
        with open(file_name, "a") as outfile:
            json.dump(final_res, outfile)
        if html_out:
            html_begin += (
                "<table style=\"border-style: solid; width: 100%; margin-left: auto; margin-right: auto;\" border=\"1\" width=\"100%\">"
                "<tbody><tr style=\"background: #12294d; color: #ffffff; text-align: left;\"><td>" + task +
                "</td></tr><tr><td style=\"text-align: left;\"><pre style=\"line-height: 0.8em;\"><span>" +
                result_html +
                "</span></pre></td></tr></tbody></table><br><br>"
            )
    
    print(Fore.BLUE + separator)
    
    package_info = perform_scan('app.package.info -a', p_name)
    format_data("Package Information", package_info, f_json)
    print(separator)
    
    activity_info = perform_scan('app.activity.info -i -u -a', p_name)
    format_data("Activities Information", activity_info, f_json)
    print(separator)
    
    broadcast_info = perform_scan('app.broadcast.info -i -u -a', p_name)
    format_data("Broadcast Receivers Information", broadcast_info, f_json)
    print(separator)
    
    attacksurface_info = perform_scan('app.package.attacksurface', p_name)
    format_data("Attack Surface Information", attacksurface_info, f_json)
    print(separator)
    
    backupapi_info = perform_scan('app.package.backup -f', p_name)
    format_data("Package with Backup API Information", backupapi_info, f_json)
    print(separator)
    
    manifest_info = perform_scan('app.package.manifest', p_name)
    format_data("Android Manifest File", manifest_info, f_json)
    print(separator)
    
    nativelib_info = perform_scan('app.package.native', p_name)
    format_data("Native Libraries used", nativelib_info, f_json)
    print(separator)
    
    contentprovider_info = perform_scan('app.provider.info -u -a', p_name)
    format_data("Content Provider Information", contentprovider_info, f_json)
    print(separator)
    
    finduri_info = perform_scan('app.provider.finduri', p_name)
    format_data("Content Provider URIs", finduri_info, f_json)
    print(separator)
    
    services_info = perform_scan('app.service.info -i -u -a', p_name)
    format_data("Services Information", services_info, f_json)
    print(separator)
    
    nativecomponents_info = perform_scan('scanner.misc.native -a', p_name)
    format_data("Native Components in Package", nativecomponents_info, f_json)
    print(separator)
    
    worldreadable_info = perform_scan('scanner.misc.readablefiles /data/data/' + p_name + '/', p_name, 1)
    format_data("World Readable Files in App Installation Location", worldreadable_info, f_json)
    print(separator)
    
    worldwriteable_info = perform_scan('scanner.misc.readablefiles /data/data/' + p_name + '/', p_name, 1)
    format_data("World Writeable Files in App Installation Location", worldwriteable_info, f_json)
    print(separator)
    
    querycp_info = perform_scan('scanner.provider.finduris -a', p_name)
    format_data("Content Providers Query from Current Context", querycp_info, f_json)
    print(separator)
    
    sqli_info = perform_scan('scanner.provider.injection -a', p_name)
    format_data("SQL Injection on Content Providers", sqli_info, f_json)
    print(separator)
    
    sqltables_info = perform_scan('scanner.provider.sqltables -a', p_name)
    format_data("SQL Tables using SQL Injection", sqltables_info, f_json)
    print(separator)
    
    dirtraversal_info = perform_scan('scanner.provider.traversal -a', p_name)
    format_data("Directory Traversal using Content Provider", dirtraversal_info, f_json)
    print(separator)
    
    html_begin += "</body></html>"
    with open(f_html, "wb") as f:
        f.write(html_begin.encode("utf-8"))
    
    print("\nAll the results are stored in " + file_name + " (JSON, TXT, and HTML files).")
    print(separator)


