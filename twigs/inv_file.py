import sys
import platform
import os
import logging
import PyPDF4

def get_products_from_pdf_file(in_file):
    logging.info("Retriving products from PDF file [%s]" % in_file)
    pdf_fd = open(in_file, 'rb')
    pdfFileReader = PyPDF4.PdfFileReader(pdf_fd)
    complete_text = ''
    for page_num in range(pdfFileReader.numPages):
        pdfPage = pdfFileReader.getPage(page_num)
        page_text = pdfPage.extractText()
        complete_text = complete_text + page_text
    products = []
    join = False
    for i in complete_text.split('\n'):
        for j in i.split(','):
            j = j.strip()
            if len(j) > 0 and j != '!' and j.isdigit() == False:
                j = j.replace(u'\xde','fi')
                if join == True:
                    join = False
                    products[-1] = products[-1] + j
                    continue
                if j == '"':
                    join = True
                    products[-1] = products[-1] + 'ff'
                    continue
                products.append(j)
    logging.info("Done retriving products from PDF file")
    return products

def get_inventory(args):
    # Note this is a workaround since 'in' is a reserved word and hence one cannot do args.in
    temp_dict = vars(args)
    in_file = temp_dict['in']

    if os.path.isfile(in_file) == False:
        logging.error("Error specified file [%s] not found...", in_file)
        sys.exit(1)
    temp = in_file.rfind('.')
    if temp == -1:
        logging.error('Error specified file [%s] is missing extension...', in_file)
        sys.exit(1)
    in_file_ext = in_file[temp+1:]
    if in_file_ext == 'pdf':
        products = get_products_from_pdf_file(in_file)
    else:
        logging.error('Error unsupported input file type specified...')
        sys.exit(1)
    
    if args.assetid is None:
        asset_id = os.path.basename(in_file)
        temp = asset_id.rfind('.')
        asset_id = asset_id[:temp] # remove the extension
    else:
        asset_id = args.assetid
    asset_id = asset_id.replace('/','-')
    asset_id = asset_id.replace(':','-')
    if args.assetname is not None:
        asset_name = args.assetname.replace('/','-')
        asset_name = asset_name.replace(':','-')
    else:
        asset_name = asset_id

    asset = { }
    asset['id'] = asset_id
    asset['name'] = asset_name
    if args.type == 'OpenSource':
        asset['type'] = 'Open Source'
    else:
        asset['type'] = 'Other'
    asset['owner'] = args.handle
    asset['products'] = products
    assets = [ asset ]
    return assets

