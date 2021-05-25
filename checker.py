from __future__ import division, print_function
import pefile
import array
import math
import pickle
import os
from flask import Flask, request, render_template,redirect, url_for
from feature_Extraction import create_vector_single,extract_features
from werkzeug.utils import secure_filename
import joblib
import numpy as np

# Keras
from tensorflow.keras.applications.imagenet_utils import preprocess_input, decode_predictions
from tensorflow.keras.models import load_model
from tensorflow.keras.preprocessing import image



MODEL_PATH ='dense3.h5'

# Load your trained model
model = load_model(MODEL_PATH)

def cutit(s,n):
   return s[n:]

app = Flask(__name__)

app.config['UPLOAD_FOLDER'] = "uploads/"


@app.route('/')
def home():
    return render_template('index.html')
@app.route('/apk')
def come():
    return render_template('index1.html')

@app.route('/exe')
def dome():
    return render_template('index2.html')

@app.route('/image')
def mome():
    return render_template('index3.html')

def model_predict(img_path, model):
    img = image.load_img(img_path, target_size=(224, 224))

    # Preprocessing the image
    x = image.img_to_array(img)
    # x = np.true_divide(x, 255)
    ## Scaling
    x=x/255
    x = np.expand_dims(x, axis=0)
   
    preds = model.predict(x)
    preds=np.argmax(preds, axis=1)
    print(preds)
    if preds==0:
        preds="This is Good ware"
    #elif preds==1:
    #    preds="This is Good ware"
    else:
        preds="This is Malware"
    
    
    return preds

@app.route('/predict', methods=['GET', 'POST'])
def upload():
    if request.method == 'POST':
        # Get the file from post request
        f = request.files['file']

        # Save the file to ./uploads
        basepath = os.path.dirname(__file__)
        file_path = os.path.join(
            basepath, 'uploads', secure_filename(f.filename))
        f.save(file_path)

        # Make prediction
        preds = model_predict(file_path, model)
        result=preds
        return result
    return None

@app.route('/predict1', methods=['POST'])
def analyze():
    if request.method == 'POST':
        f = request.files.get('file', None)
        if f:
            fp = os.path.join(app.config['UPLOAD_FOLDER'], f.filename)
            f.save(fp)
            features = extract_features(fp)
            feature_vector = create_vector_single(features)
            arr = []
            arr.append(feature_vector)
            mod1 = pickle.load(open("feature_model.p", "rb"))
            mod2 = pickle.load(open("kfold_train_data.p", "rb"))
            mod3 = pickle.load(open("decision.p", "rb"))
            mod4 = pickle.load(open("random_forest.p", "rb"))
            mod5 = pickle.load(open("xgb.p", "rb"))
            mod6 = pickle.load(open("pca_decision.p", "rb"))
            mod7 = pickle.load(open("pca_ran.p", "rb"))
            feature_vector_new = mod1.transform(arr)
            feature_vector_dec = mod6.transform(feature_vector_new)
            feature_vector_ran = mod7.transform(feature_vector_new)
            label = {}
            result = mod2.predict(feature_vector_new)
            if int(result[0]) == 1:
                label["svm"] = "Malware"
            else:
                label["svm"] = "Goodware"

            result = mod5.predict(feature_vector_new)
            if int(result[0]) == 1:
                label["xgb"] = "Malware"
            else:
                label["xgb"] = "Goodware"

            result = mod4.predict(feature_vector_ran)
            if int(result[0]) == 1:
                label["random_forest"] = "Malware"
            else:
                label["random_forest"] = "Goodware"
            result = mod3.predict(feature_vector_dec)
            if int(result[0]) == 1:
                label["Decision_tree"] = "Malware"
            else:
                label["Decision_tree"] = "Goodware"
        else:
            label = None

    return render_template("index1.html", label=label)

@app.route('/result')
def res():
	return render_template("result1.html")
	
@app.route('/uploader', methods = ['GET', 'POST'])
def upload_file():
   if request.method == 'POST':
    f = request.files['file']
    f.save(f.filename)
    ##########################################
    # Load classifier
    clf = joblib.load(os.path.join(os.path.dirname(os.path.realpath(__file__)),'classifier/classifier.pkl'))
    features =pickle.loads(open(os.path.join(os.path.dirname(os.path.realpath(__file__))
                                       ,'classifier/features.pkl'),'rb').read())
     ##########################################
     #tweet = request.form['tweet']
     #tweet=cutit(f.filename, 12)
    tweet =f.filename
    print(tweet)
     #########################################
    data = extract_infos(tweet)
    monimala= map(lambda x: data[x], features)
    pe_features=list(monimala)
    res = clf.predict([pe_features])[0]
        #########################################
     #print('The file %s is %s' % (os.path.basename(sys.argv[1]),['malicious', 'legitimate'][res]))
    return render_template('result.html', prediction = ['malicious', 'legitimate'][res])





































#The phrase File Entropy is used to measure the amount of data which is present in a selected file. For example, if you have some files and desire to calculate the entropy value for that, then it will be very simple by accessing the methods of File Entropy and its calculation process.
def get_entropy(data):
    if len(data) == 0:
        return 0.0
    occurences = array.array('L', [0] * 256)
    for x in data:
        occurences[x if isinstance(x, int) else ord(x)] += 1

    entropy = 0
    for x in occurences:
        if x:
            p_x = float(x) / len(data)
            entropy -= p_x * math.log(p_x, 2)
    return entropy


def get_resources(pe):
    """Extract resources :
    [entropy, size]"""
    resources = []
    if hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE'):
        try:
            for resource_type in pe.DIRECTORY_ENTRY_RESOURCE.entries:
                if hasattr(resource_type, 'directory'):
                    for resource_id in resource_type.directory.entries:
                        if hasattr(resource_id, 'directory'):
                            for resource_lang in resource_id.directory.entries:
                                data = pe.get_data(resource_lang.data.struct.OffsetToData,
                                                   resource_lang.data.struct.Size)
                                size = resource_lang.data.struct.Size
                                entropy = get_entropy(data)

                                resources.append([entropy, size])
        except Exception as e:
            return resources
    return resources


def get_version_info(pe):
    """Return version infos"""
    res = {}
    for fileinfo in pe.FileInfo:
        if fileinfo.Key == 'StringFileInfo':
            for st in fileinfo.StringTable:
                for entry in st.entries.items():
                    res[entry[0]] = entry[1]
        if fileinfo.Key == 'VarFileInfo':
            for var in fileinfo.Var:
                res[var.entry.items()[0][0]] = var.entry.items()[0][1]
    if hasattr(pe, 'VS_FIXEDFILEINFO'):
        res['flags'] = pe.VS_FIXEDFILEINFO.FileFlags
        res['os'] = pe.VS_FIXEDFILEINFO.FileOS
        res['type'] = pe.VS_FIXEDFILEINFO.FileType
        res['file_version'] = pe.VS_FIXEDFILEINFO.FileVersionLS
        res['product_version'] = pe.VS_FIXEDFILEINFO.ProductVersionLS
        res['signature'] = pe.VS_FIXEDFILEINFO.Signature
        res['struct_version'] = pe.VS_FIXEDFILEINFO.StrucVersion
    return res


def extract_infos(fpath):
    res = {}
    pe = pefile.PE(fpath)
    res['Machine'] = pe.FILE_HEADER.Machine
    res['SizeOfOptionalHeader'] = pe.FILE_HEADER.SizeOfOptionalHeader
    res['Characteristics'] = pe.FILE_HEADER.Characteristics
    res['MajorLinkerVersion'] = pe.OPTIONAL_HEADER.MajorLinkerVersion
    res['MinorLinkerVersion'] = pe.OPTIONAL_HEADER.MinorLinkerVersion
    res['SizeOfCode'] = pe.OPTIONAL_HEADER.SizeOfCode
    res['SizeOfInitializedData'] = pe.OPTIONAL_HEADER.SizeOfInitializedData
    res['SizeOfUninitializedData'] = pe.OPTIONAL_HEADER.SizeOfUninitializedData
    res['AddressOfEntryPoint'] = pe.OPTIONAL_HEADER.AddressOfEntryPoint
    res['BaseOfCode'] = pe.OPTIONAL_HEADER.BaseOfCode
    try:
        res['BaseOfData'] = pe.OPTIONAL_HEADER.BaseOfData
    except AttributeError:
        res['BaseOfData'] = 0
    res['ImageBase'] = pe.OPTIONAL_HEADER.ImageBase
    res['SectionAlignment'] = pe.OPTIONAL_HEADER.SectionAlignment
    res['FileAlignment'] = pe.OPTIONAL_HEADER.FileAlignment
    res['MajorOperatingSystemVersion'] = pe.OPTIONAL_HEADER.MajorOperatingSystemVersion
    res['MinorOperatingSystemVersion'] = pe.OPTIONAL_HEADER.MinorOperatingSystemVersion
    res['MajorImageVersion'] = pe.OPTIONAL_HEADER.MajorImageVersion
    res['MinorImageVersion'] = pe.OPTIONAL_HEADER.MinorImageVersion
    res['MajorSubsystemVersion'] = pe.OPTIONAL_HEADER.MajorSubsystemVersion
    res['MinorSubsystemVersion'] = pe.OPTIONAL_HEADER.MinorSubsystemVersion
    res['SizeOfImage'] = pe.OPTIONAL_HEADER.SizeOfImage
    res['SizeOfHeaders'] = pe.OPTIONAL_HEADER.SizeOfHeaders
    res['CheckSum'] = pe.OPTIONAL_HEADER.CheckSum
    res['Subsystem'] = pe.OPTIONAL_HEADER.Subsystem
    res['DllCharacteristics'] = pe.OPTIONAL_HEADER.DllCharacteristics
    res['SizeOfStackReserve'] = pe.OPTIONAL_HEADER.SizeOfStackReserve
    res['SizeOfStackCommit'] = pe.OPTIONAL_HEADER.SizeOfStackCommit
    res['SizeOfHeapReserve'] = pe.OPTIONAL_HEADER.SizeOfHeapReserve
    res['SizeOfHeapCommit'] = pe.OPTIONAL_HEADER.SizeOfHeapCommit
    res['LoaderFlags'] = pe.OPTIONAL_HEADER.LoaderFlags
    res['NumberOfRvaAndSizes'] = pe.OPTIONAL_HEADER.NumberOfRvaAndSizes

    # Sections
    res['SectionsNb'] = len(pe.sections)
    jitul = map(lambda x: x.get_entropy(), pe.sections)
    entropy=list(jitul)
    #print(list(entropy))
    a=len(list(entropy))
    res['SectionsMeanEntropy'] = sum(entropy) / float(a)
    res['SectionsMinEntropy'] = min(entropy)
    res['SectionsMaxEntropy'] = max(entropy)
    manish= map(lambda x: x.SizeOfRawData, pe.sections)
    raw_sizes=list(manish)
    b=len(list(raw_sizes))

    res['SectionsMeanRawsize'] = sum(raw_sizes) / float(b)
    res['SectionsMinRawsize'] = min(raw_sizes)
    res['SectionsMaxRawsize'] = max(raw_sizes)
    sumit = map(lambda x: x.Misc_VirtualSize, pe.sections)
    virtual_sizes=list(sumit)
    c=len(list(virtual_sizes))

    res['SectionsMeanVirtualsize'] = sum(virtual_sizes) / float(c)
    res['SectionsMinVirtualsize'] = min(virtual_sizes)
    res['SectionMaxVirtualsize'] = max(virtual_sizes)

    # Imports
    try:
        res['ImportsNbDLL'] = len(pe.DIRECTORY_ENTRY_IMPORT)
        imports = sum([x.imports for x in pe.DIRECTORY_ENTRY_IMPORT], [])
        res['ImportsNb'] = len(imports)
        res['ImportsNbOrdinal'] = len(list(filter(lambda x: x.name is None, imports)))
    except AttributeError:
        res['ImportsNbDLL'] = 0
        res['ImportsNb'] = 0
        res['ImportsNbOrdinal'] = 0

    # Exports
    try:
        res['ExportNb'] = len(pe.DIRECTORY_ENTRY_EXPORT.symbols)
    except AttributeError:
        # No export
        res['ExportNb'] = 0
    # Resources
    resources = get_resources(pe)
    res['ResourcesNb'] = len(resources)
    if len(resources) > 0:
        monika = map(lambda x: x[0], resources)
        entr=list(monika)
        d=len(list(entropy))

        res['ResourcesMeanEntropy'] = sum(entr) / float(d)
        res['ResourcesMinEntropy'] = min(entr)
        res['ResourcesMaxEntropy'] = max(entr)
        cat = map(lambda x: x[1], resources)
        sizes=list(cat)
        e=len(list(sizes))
        res['ResourcesMeanSize'] = sum(sizes) / float(e)
        res['ResourcesMinSize'] = min(sizes)
        res['ResourcesMaxSize'] = max(sizes)
    else:
        res['ResourcesNb'] = 0
        res['ResourcesMeanEntropy'] = 0
        res['ResourcesMinEntropy'] = 0
        res['ResourcesMaxEntropy'] = 0
        res['ResourcesMeanSize'] = 0
        res['ResourcesMinSize'] = 0
        res['ResourcesMaxSize'] = 0

    # Load configuration size
    try:
        res['LoadConfigurationSize'] = pe.DIRECTORY_ENTRY_LOAD_CONFIG.struct.Size
    except AttributeError:
        res['LoadConfigurationSize'] = 0

    # Version configuration size
    try:
        version_infos = get_version_info(pe)
        res['VersionInformationSize'] = len(version_infos.keys())
    except AttributeError:
        res['VersionInformationSize'] = 0
    return res

if __name__ == '__main__':
  app.run(debug = True)
