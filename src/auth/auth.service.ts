import { ForbiddenException, HttpException, Injectable } from '@nestjs/common';
import { User, Bookmark } from '@prisma/client';
import { PrismaService } from 'src/prisma/prisma.service';
import { authDto } from './dto';
import * as argon from 'argon2';
@Injectable()
export class AuthService {
  constructor(private prisma: PrismaService) {}

  async signup(dto: authDto) {
    //   generate password
    const hash = await argon.hash(dto.password);
    // save the new user in the db
    const user = await this.prisma.user.create({
      data: {
        email: dto.email,
        hash,
        firstname: dto.firstname,
        lastname: dto.lastname,
      },
    });

    //   return the saved user
    delete user.hash;
    return user;
  }

  async signin(dto: authDto) {
    // find user by email
    const user = await this.prisma.user.findFirst({
      where: {
        email: dto.email,
      },
    });
    // if user dosent exist throw execption
    if (!user) {
      throw new ForbiddenException('No user found');
    }
    // compare password
    const passwordMatch = await argon.verify(user.hash, dto.password);
    // if password incorrect throw exception
    if (!passwordMatch) {
      throw new ForbiddenException('password doesent match');
    }
    // send back the user
    delete user.hash;

    return user;
  }
}
