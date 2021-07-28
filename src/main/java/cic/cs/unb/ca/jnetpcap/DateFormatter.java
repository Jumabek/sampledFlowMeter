package cic.cs.unb.ca.jnetpcap;

import java.text.SimpleDateFormat;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.Date;
import java.time.ZoneId;

public class DateFormatter {
	
	public static String parseDateFromLong(long time, String format){
		try{
			if (format == null){
				format = "dd/MM/yyyy hh:mm:ss";					
			}
			SimpleDateFormat simpleFormatter = new SimpleDateFormat(format);
			Date tempDate = new Date(time);
			return simpleFormatter.format(tempDate);
		}catch(Exception ex){
			System.out.println(ex.toString());
			return "dd/MM/yyyy hh:mm:ss";
		}		
	}

//	public static tzConverter(ZoneId zoneId1,ZoneId zoneId2,LocalDateTime ldt){
//
//		System.out.println("TimeZone : " + zoneId1);
//		System.out.println("TimeZone : " + zoneId1);
//
//		//LocalDateTime + ZoneId = ZonedDateTime
//		ZonedDateTime asiaZonedDateTime = ldt.atZone(singaporeZoneId);
//		System.out.println("Date (Singapore) : " + asiaZonedDateTime);
//
//		ZoneId newYokZoneId = ZoneId.of("America/New_York");
//		System.out.println("TimeZone : " + newYokZoneId);
//
//		ZonedDateTime nyDateTime = asiaZonedDateTime.withZoneSameInstant(newYokZoneId);
//	}

	public static String convertMilliseconds2String(long time, String format) {

        if (format == null){
            format = "dd/MM/yyyy hh:mm:ss";
        }

        DateTimeFormatter formatter = DateTimeFormatter.ofPattern(format);
        //ZoneId default_znId = ZoneId.systemDefault();
        ZoneId znId = ZoneId.of("Canada/Atlantic");

        LocalDateTime ldt = LocalDateTime.ofInstant(Instant.ofEpochMilli(time),znId );

        return ldt.format(formatter);
	}

}
