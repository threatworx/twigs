import sys
import platform
import os
import logging
import PyPDF4
from pdfminer.pdfparser import PDFParser
from pdfminer.pdfdocument import PDFDocument
from pdfminer.pdfpage import PDFPage
from pdfminer.pdfpage import PDFTextExtractionNotAllowed
from pdfminer.pdfinterp import PDFResourceManager
from pdfminer.pdfinterp import PDFPageInterpreter
from pdfminer.converter import PDFPageAggregator
from pdfminer.layout import LAParams, LTTextBox, LTTextLine, LTText

def get_products_from_pdf_file_using_pypdf(in_file):
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
    return products

def get_products_from_pdf_file_using_pdfminer(in_file):
    logging.getLogger("pdfminer").setLevel(logging.WARNING)
    products = []
    fp = open(in_file, 'rb')
    parser = PDFParser(fp)
    password = ''
    document = PDFDocument(parser, password)
    # Check if the document allows text extraction. If not, abort.
    if not document.is_extractable:
        fp.close()
        logging.error("PDF document [%s] does not allow Text Extraction", in_file)
        return products
    rsrcmgr = PDFResourceManager()
    laparams = LAParams()
    device = PDFPageAggregator(rsrcmgr, laparams=laparams)
    interpreter = PDFPageInterpreter(rsrcmgr, device)

    complete_text = ''
    for page in PDFPage.create_pages(document):
        interpreter.process_page(page)
        layout = device.get_result()
        for lt_obj in layout:
            if isinstance(lt_obj, LTTextBox) or isinstance(lt_obj, LTTextLine):
                complete_text = complete_text + lt_obj.get_text()

    for i in complete_text.split('\n'):
        for j in i.split(','):
            j = j.strip()
            products.append(j)
    return products

def get_assets_from_csv_file(in_file):
    assets = []
    with open(in_file, "r") as fd:
        line  = fd.readline()
        while line:
            tokens = line.split(',')
            asset = { }
            asset['id'] = tokens[0]
            asset['name'] = tokens[1]
            asset['type'] = tokens[2]
            for i in range(3, len(tokens)):
                token = tokens[i]
                if token.startswith(':OWNER:'):
                    asset['owner'] = token[7:]
                elif token.startswith(':TAG:'):
                    if asset.get('tags') is None:
                        asset['tags'] = []
                    asset['tags'].append(token[5:])
                else:
                    if asset.get('products') is None:
                        asset['products'] = []
                    asset['products'].append(token)
            assets.append(asset)
            line = fd.readline()
    return assets

def enumerate_files(in_path, file_ext):
    ret_files = []
    for root, subdirs, files in os.walk(in_path):
        for fname in files:
            file_path = os.path.join(root, fname)
            if file_path.endswith(file_ext):
                ret_files.append(file_path)
    return ret_files

def get_inventory(args):
    # Note this is a workaround since 'in' is a reserved word and hence one cannot do args.in
    temp_dict = vars(args)
    in_file = temp_dict['in']

    if os.path.isdir(in_file):
        logging.info("Processing CSV files in specified directory [%s]", in_file)
        csv_files = enumerate_files(in_file, '.csv')
        assets = []
        for csv_file in csv_files:
            logging.info("Retriving products from CSV file [%s]", csv_file)
            temp_assets = get_assets_from_csv_file(csv_file)
            assets.extend(temp_assets)
        return assets
    elif os.path.isfile(in_file) == False:
        logging.error("Error specified file [%s] not found...", in_file)
        sys.exit(1)
    temp = in_file.rfind('.')
    if temp == -1:
        logging.error('Error specified file [%s] is missing extension...', in_file)
        sys.exit(1)
    in_file_ext = in_file[temp+1:]
    if in_file_ext == 'pdf':
        logging.info("Retriving products from PDF file [%s]", in_file)
        products = get_products_from_pdf_file_using_pypdf(in_file)
        if len(products) == 0:
            products = get_products_from_pdf_file_using_pdfminer(in_file)
        logging.info("Done retriving products from PDF file")
    elif in_file_ext == 'csv':
        logging.info("Retriving products from CSV file [%s]", in_file)
        assets = get_assets_from_csv_file(in_file)
        return assets
    else:
        logging.error('Error unsupported input file type specified...')
        sys.exit(1)
    
    if args.assetid is None:
        asset_id = os.path.basename(in_file)
        temp = asset_id.rfind('.')
        asset_id = asset_id[:temp] # remove the extension
    else:
        asset_id = args.assetid
    asset_id = asset_id.replace(' ','-')
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
    if args.type == 'repo':
        asset['type'] = 'Source Repository'
    else:
        asset['type'] = 'Other'
    asset['owner'] = args.handle
    asset['products'] = products
    assets = [ asset ]
    return assets

