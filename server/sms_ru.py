import os
import logging
import httpx
from typing import Optional
from server.config import APP_NAME

logger = logging.getLogger("meno.sms_ru")

# Настройки API SMS.RU
# Значения по умолчанию, которые будут переопределены переменными окружения
SMS_RU_API_KEY = os.environ.get("MENO_SMS_RU_API_KEY", "")
SMS_RU_SENDER = os.environ.get("MENO_SMS_RU_SENDER", "MeNo")

async def send_sms(phone: str, text: str) -> bool:
    """
    Отправка SMS через API SMS.RU.
    
    :param phone: Номер телефона в международном формате (например, '79991234567')
    :param text: Текст сообщения
    :return: True если отправлено успешно, иначе False
    """
    if not SMS_RU_API_KEY:
        logger.error("SMS.RU API Key is not configured in environment variables (MENO_SMS_RU_API_KEY)")
        return False

    # SMS.RU API endpoint
    url = "https://sms.ru/sms/send"
    
    params = {
        "api_id": SMS_RU_API_KEY,
        "to": phone,
        "msg": text,
        "sender": SMS_RU_SENDER,
        "type": "text"
    }

    try:
        # Используем AsyncClient для неблокирующих запросов
        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.get(url, params=params)
            response.raise_for_status()
            data = response.json()
            
            # SMS.RU возвращает статус в поле 'status'. 
            # Успешная отправка или постановка в очередь возвращает 'OK'
            if data.get("status") == "OK":
                logger.info(f"SMS successfully sent to {phone} via SMS.RU")
                return True
            
            logger.error(f"SMS.RU API error: {data.get('status')} - {data.get('description')}")
            return False
            
    except httpx.HTTPStatusError as e:
        logger.error(f"SMS.RU HTTP status error: {e.response.status_code} for {phone}")
        return False
    except httpx.RequestError as e:
        logger.error(f"SMS.RU request error: {e}")
        return False
    except Exception as e:
        logger.error(f"Unexpected error sending SMS via SMS.RU to {phone}: {e}")
        return False
