import { Injectable } from '@nestjs/common';
import { User, Bookmark} from '@prisma/client';

@Injectable()
export class AuthService {
   async login(): Promise<string>{
       return 'Helllo'
   }
}
