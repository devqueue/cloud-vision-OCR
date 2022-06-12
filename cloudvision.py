import os
from google.cloud import vision
from google.cloud import vision_v1
# from google.cloud.vision_v1 import types
import pandas as pd
import cv2
from PIL import Image


os.environ['GOOGLE_APPLICATION_CREDENTIALS'] = r'prefab-research-352802-3773376dfad4.json'

client = vision.ImageAnnotatorClient()


def preprocess(img):
    images = []
    image = cv2.imread(img)
    gray = cv2.cvtColor(image, cv2.COLOR_BGR2GRAY)
    blur = cv2.GaussianBlur(gray, (7,7), 0)
    thresh = cv2.threshold(blur, 0, 255, cv2.THRESH_BINARY_INV+ cv2.THRESH_OTSU)[1]

    kernal = cv2.getStructuringElement(cv2.MORPH_RECT, (25, 4))
    dialate = cv2.dilate(thresh, kernal, iterations=1)

    name = img.split('/')[-1].split('.')[0]
    print(name)

    # find contours
    cnts = cv2.findContours(dialate, cv2.RETR_EXTERNAL, cv2.CHAIN_APPROX_SIMPLE)
    cnts = cnts[0] if len(cnts) ==2 else cnts[1]

    cnts = sorted(cnts, key=lambda x: cv2.boundingRect(x)[0])
    count = 0


    for c in cnts:
        x, y, w, h = cv2.boundingRect(c)
        if h > 10 and w > 10:
            roi = image[y:y+h, x:x+w]
            img_str = cv2.imencode('.png', roi)[1].tobytes()
            images.append(img_str)
            count+=1
    return images




def detectText(images: list, name: str):
    df = pd.DataFrame(columns=['locale', 'description'])
    print(f"[INFO]: {len(images)} images recieved")

    for img in images:

        image = vision_v1.types.Image(content=img)
        response = client.text_detection(image=image)
        texts = response.text_annotations

        for text in texts:
            temp = pd.DataFrame(dict(locale=text.locale, description=text.description, index=[0]),)
            df = pd.concat([df, temp],ignore_index= True)
            break
    
    df.to_csv(f'{name}.csv')
    return df

FILE_NAME = 'testing_artifacts/input/nooruddin.jpg'
OUTPUT = 'testing_artifacts/output'
FOLDER_PATH = r'.'
segment_list = preprocess(FILE_NAME)

print(detectText(segment_list, f'{OUTPUT}/nooruddin'))